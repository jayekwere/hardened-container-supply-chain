#!/usr/bin/env python3
"""Create local-only signed negative fixtures; never write to the public registry."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time
import urllib.request

kubeconfig, cluster = sys.argv[1:]
if not cluster.startswith('hsc-admission-'):
    raise SystemExit('explicit disposable cluster required')
root = Path.cwd()
work = root / '.tools' / ('attestation-fixtures-' + cluster)
work.mkdir(mode=0o700)
tls = work / 'tls'
tls.mkdir(mode=0o700)
lock = json.loads(Path('integration/admission/inputs.lock.json').read_text())
image = lock['signedImage']
digest = image.split('@sha256:')[1]
environment = dict(os.environ, COSIGN_PASSWORD=secrets.token_urlsafe(32))
environment.pop('COSIGN_REPOSITORY', None)


def run(*args, env=None):
    result = subprocess.run(args, env=env, timeout=180, capture_output=True, text=True)
    if result.returncode:
        print(result.stderr, file=sys.stderr)
        result.check_returncode()
    return result.stdout.strip()


def kubectl(*args):
    return run('kubectl', '--kubeconfig', kubeconfig, *args)


(tls / 'tls.conf').write_text('''[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=attestation-registry.test
[ext]
subjectAltName=DNS:attestation-registry.test,IP:127.0.0.1
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage=serverAuth
''')
run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '1',
    '-config', str(tls / 'tls.conf'), '-keyout', str(tls / 'tls.key'), '-out', str(tls / 'tls.crt'))
registry = cluster + '-registry'
run('docker', 'run', '-d', '--name', registry, '--network', 'kind',
    '-p', '127.0.0.1::5000', '-v', str(tls) + ':/certs:ro',
    '-e', 'OTEL_TRACES_EXPORTER=none',
    '-e', 'REGISTRY_HTTP_TLS_CERTIFICATE=/certs/tls.crt',
    '-e', 'REGISTRY_HTTP_TLS_KEY=/certs/tls.key', lock['fixtureRegistryImage'])
info = json.loads(run('docker', 'inspect', registry))[0]
address = info['NetworkSettings']['Networks']['kind']['IPAddress']
port = info['NetworkSettings']['Ports']['5000/tcp'][0]['HostPort']
host = '127.0.0.1:' + port
context = ssl.create_default_context(cafile=str(tls / 'tls.crt'))
for attempt in range(30):
    try:
        with urllib.request.urlopen('https://' + host + '/v2/', context=context, timeout=2) as response:
            assert response.status == 200
        break
    except (OSError, urllib.error.URLError):
        if attempt == 29:
            raise
        time.sleep(1)

kubectl('-n', 'image-policy-system', 'create', 'configmap', 'attestation-fixture-ca',
        '--from-file=ca.crt=' + str(tls / 'tls.crt'))
patch = [
    {'op': 'add', 'path': '/spec/template/spec/hostAliases', 'value': [{'ip': address, 'hostnames': ['attestation-registry.test']}]},
    {'op': 'add', 'path': '/spec/template/spec/volumes/-', 'value': {'name': 'fixture-ca', 'configMap': {'name': 'attestation-fixture-ca'}}},
    {'op': 'add', 'path': '/spec/template/spec/containers/0/volumeMounts/-', 'value': {'name': 'fixture-ca', 'mountPath': '/etc/fixture-ca', 'readOnly': True}},
    {'op': 'add', 'path': '/spec/template/spec/containers/0/env/-', 'value': {'name': 'SSL_CERT_DIR', 'value': '/etc/fixture-ca:/etc/ssl/certs'}},
]
kubectl('-n', 'image-policy-system', 'patch', 'deployment', 'policy-controller-webhook', '--type=json', '--patch', json.dumps(patch))
kubectl('-n', 'image-policy-system', 'rollout', 'status', 'deployment/policy-controller-webhook', '--timeout=120s')
for key in ('trusted', 'rogue'):
    run('cosign', 'generate-key-pair', '--output-key-prefix', str(work / key), env=environment)

sbom_type = 'https://cyclonedx.org/bom'
evidence_type = 'https://github.com/jayekwere/hardened-container-supply-chain/evidence/v1'
profile = lock['attestationProfile']
sbom = {'bomFormat': 'CycloneDX', 'specVersion': profile['sbomSpecVersion'], 'version': 1,
        'components': [{'name': 'stdlib', 'type': 'library', 'version': profile['stdlibVersion'],
                        'purl': 'pkg:golang/stdlib@' + profile['stdlibVersion']}]}
evidence = {'schemaVersion': 1, 'sourceRevision': lock['attestationProfile']['sourceRevision'],
            'image': image, 'builder': 'release.yml', 'platform': profile['platform'],
            'generatedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'checksums': {name: hashlib.sha256(('synthetic fixture: ' + name).encode()).hexdigest()
                          for name in ('scan.json', 'sbom.cdx.json', 'db-metadata.json', 'scanner-version.txt')},
            'exceptions': {'schemaVersion': 1, 'entries': []}}


def envelope(name, predicate_type, predicate, key='trusted', subject=digest):
    path = work / (name + '-predicate.json')
    path.write_text(json.dumps(predicate))
    raw = run('cosign', 'attest', '--yes', '--key', str(work / (key + '.key')), '--tlog-upload=false',
              '--no-upload', '--predicate', str(path), '--type', predicate_type,
              image.split('@')[0] + '@sha256:' + subject, env=environment)
    result = work / (name + '-envelope.json')
    result.write_text(raw + '\n')
    return result


good_sbom = envelope('good-sbom', sbom_type, sbom)
good_evidence = envelope('good-evidence', evidence_type, evidence)
bad_sbom = envelope('bad-sbom', sbom_type, dict(sbom, components=[]))
bad_image = envelope('bad-image', evidence_type, dict(evidence, image=image.split('@')[0] + '@sha256:' + '0' * 64))
bad_revision = envelope('bad-revision', evidence_type, dict(evidence, sourceRevision='0' * 40))
rogue_sbom = envelope('rogue-sbom', sbom_type, sbom, key='rogue')
wrong_subject = envelope('wrong-subject', evidence_type,
                         dict(evidence, image=image.split('@')[0] + '@sha256:' + '0' * 64), subject='0' * 64)
tampered = json.loads(good_evidence.read_text())
# Preserve all valid claims while changing the signed bytes. A content-only
# checker would accept this; the signature verifier must reject it.
tampered['payload'] = base64.b64encode(base64.b64decode(tampered['payload']) + b'\n').decode()
tampered_evidence = work / 'tampered-envelope.json'
tampered_evidence.write_text(json.dumps(tampered) + '\n')
sets = {
    'complete': [good_sbom, good_evidence],
    'missing-sbom': [good_evidence],
    'missing-evidence': [good_sbom],
    'invalid-sbom': [bad_sbom, good_evidence],
    'evidence-image-mismatch': [good_sbom, bad_image],
    'evidence-revision-mismatch': [good_sbom, bad_revision],
    'untrusted-sbom': [rogue_sbom, good_evidence],
    'tampered-evidence': [good_sbom, tampered_evidence],
    'wrong-subject-evidence': [good_sbom, wrong_subject],
}
fixtures = {}
for name, envelopes in sets.items():
    repository = host + '/fixtures/' + name
    # Separate source/target CA options keep public-registry TLS verification
    # intact. Attaching uses only the local digest reference afterward.
    run('oras', 'cp', '--to-ca-file', str(tls / 'tls.crt'), image, repository + ':subject')
    flags = [arg for path in envelopes for arg in ('--attestation', str(path))]
    run('cosign', 'attach', 'attestation', '--registry-cacert', str(tls / 'tls.crt'), *flags,
        repository + '@sha256:' + digest, env=environment)
    fixtures[name] = {'source': 'attestation-registry.test:5000/fixtures/' + name,
                      'envelopeSHA256': [hashlib.sha256(path.read_bytes()).hexdigest() for path in envelopes]}
Path('artifacts/admission/fixtures.json').write_text(json.dumps({
    'schemaVersion': 1, 'image': image, 'registryImage': lock['fixtureRegistryImage'],
    'publicKey': (work / 'trusted.pub').read_text(), 'fixtures': fixtures,
    'scope': 'Synthetic predicates, ephemeral signing keys, TLS registry confined to the disposable cluster network. No fixture is published remotely. Production policies retain exact keyless identity and transparency verification.'
}, indent=2) + '\n')
for path in work.glob('*.key'):
    path.unlink()
print('PASS nine signed attestation fixture sets prepared; fixture signing keys deleted')
