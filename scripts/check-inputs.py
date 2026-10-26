#!/usr/bin/env python3
import json, re
from pathlib import Path
lock = json.loads(Path('tools.lock.json').read_text())
version = re.search(r'^go (\S+)$', Path('go.mod').read_text(), re.M).group(1)
assert lock['go']['version'] == version
assert 'golang:' + version + '-alpine@sha256:' in Path('Dockerfile').read_text()
assert '= go' + version in Path('Makefile').read_text()
assert re.search(r'golang:[^\s]+@sha256:[a-f0-9]{64} AS build', Path('Dockerfile').read_text())
for name, tool in lock.items():
    for item in tool['platforms'].values():
        assert item['url'].startswith('https://') and item['checksumSource'].startswith('https://')
        assert re.fullmatch('[a-f0-9]{64}', item['sha256']), name
print('PASS compiler pins and download locks consistent')

enforcer = json.loads(Path('integration/network-policy/enforcer.lock.json').read_text())
manifest = json.loads(Path('integration/network-policy/enforcer.json').read_text())
agent = next(item for item in manifest['items'] if item['kind'] == 'DaemonSet')
assert agent['spec']['template']['spec']['containers'][0]['image'] == enforcer['image']
assert re.search(r'@sha256:[a-f0-9]{64}$', enforcer['image'])
assert re.fullmatch('[a-f0-9]{40}', enforcer['upstreamCommit'])
print('PASS runtime policy enforcer image pinned and consistent')

admission = json.loads(Path('integration/admission/inputs.lock.json').read_text())
values = json.loads(Path('integration/admission/controller-values.json').read_text())
trust = json.loads(Path('integration/admission/release-policy.json').read_text())
assert re.fullmatch('[a-f0-9]{64}', admission['chart']['sha256'])
for field in ['controller', 'cleanupHelperImage', 'fixtureRegistryImage']:
    image = admission[field]['image'] if field == 'controller' else admission[field]
    assert re.search(r'@sha256:[a-f0-9]{64}$', image)
assert values['webhook']['image']['repository'] == 'invalid.invalid/controller-build-required'
assert values['webhook']['image']['version'] == 'sha256:' + '0' * 64
assert admission['controller']['image'] in Path('integration/admission/Controller.Dockerfile').read_text()
assert re.fullmatch('[a-f0-9]{64}', admission['controller']['sourceArchive']['sha256'])
assert admission['controller']['sourceCommit'] in admission['controller']['sourceArchive']['url']
assert admission['controller']['buildImage'].split('@')[0] == 'golang:' + version + '-alpine'
assert re.search(r'@sha256:[a-f0-9]{64}$', admission['controller']['buildImage'])
assert values['webhook']['failurePolicy'] == 'Fail'
assert values['webhook']['configData']['no-match-policy'] == 'deny'
authority = trust['spec']['authorities'][0]
assert len(trust['spec']['authorities']) == 1
assert authority['keyless']['identities'] == [{'issuer': admission['issuer'], 'subject': admission['subject']}]
assert authority['ctlog']['url'] == 'https://rekor.sigstore.dev'
assert not any(k.startswith('insecure') for k in authority['keyless'])
print('PASS admission controller pins, exact trust identity and fail-closed settings')

attestations = json.loads(Path('integration/admission/attestations-policy.json').read_text())
assert attestations['spec']['images'] == trust['spec']['images']
assert len(attestations['spec']['authorities']) == 1
attestor = attestations['spec']['authorities'][0]
for field in ['keyless', 'ctlog', 'signatureFormat']:
    assert attestor[field] == authority[field]
assert not any(field in attestor for field in ['key', 'static', 'source'])
requirements = attestor['attestations']
assert [(a['name'], a['predicateType'], a['policy']['type']) for a in requirements] == [
    ('release-sbom', 'https://cyclonedx.org/bom', 'cue'),
    ('release-evidence', 'https://github.com/jayekwere/hardened-container-supply-chain/evidence/v1', 'cue')]
profile = admission['attestationProfile']
assert profile['stdlibVersion'] == 'v' + version
assert profile['stdlibVersion'] in requirements[0]['policy']['data']
assert profile['sbomSpecVersion'] in requirements[0]['policy']['data']
assert profile['sourceRevision'] in requirements[1]['policy']['data']
assert profile['platform'] in requirements[1]['policy']['data']
print('PASS both admission attestations require exact release trust and checked content')
