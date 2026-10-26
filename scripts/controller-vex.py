#!/usr/bin/env python3
"""One bounded VEX case; all other findings still reach the unchanged scan gate."""
import copy
import datetime
import hashlib
import json
import sys
from pathlib import Path


def evaluate(report, advisory_bytes, packages, source, lock):
    assert hashlib.sha256(advisory_bytes).hexdigest() == lock['sha256'], 'advisory changed; review scope'
    advisory = json.loads(advisory_bytes)
    assert advisory['id'] == lock['id'] and len(advisory['affected']) == 1
    affected = advisory['affected'][0]
    assert affected['package'] == {'name': lock['module'], 'ecosystem': 'Go'}
    paths = [p['path'] for p in affected['ecosystem_specific']['imports']]
    prefix = lock['packagePrefix']
    assert paths and all(p == prefix or p.startswith(prefix + '/') for p in paths)
    assert len(packages) > 100 and len(packages) == len(set(packages))
    assert hashlib.sha256(('\n'.join(packages)+'\n').encode()).hexdigest() == source['packageClosureSHA256'], 'package closure differs from binary build record'
    assert 'github.com/sigstore/policy-controller/cmd/webhook' in packages
    assert any(p.startswith(lock['module'] + '/') for p in packages)
    assert not any(p == prefix or p.startswith(prefix + '/') for p in packages), 'affected package is compiled'
    assert source['architecture'] in ['amd64', 'arm64']
    assert report['Metadata']['ImageID'].startswith('sha256:')
    filtered = copy.deepcopy(report)
    removed = []
    for result in filtered['Results']:
        remaining = []
        for finding in result.get('Vulnerabilities', []):
            if finding['VulnerabilityID'] == lock['id']:
                assert result['Type'] == 'gobinary' and finding['PkgName'] == lock['module']
                assert finding['Severity'] == 'UNKNOWN' and finding['InstalledVersion']
                assert any(p['Name'] == lock['module'] and p['Version'] == finding['InstalledVersion'] for p in result['Packages'])
                removed.append(finding)
            else:
                remaining.append(finding)
        result['Vulnerabilities'] = remaining
    assert len(removed) == 1, 'bounded VEX case absent or ambiguous; review inventory'
    return filtered, removed[0]


if __name__ == '__main__':
    a = Path('artifacts/controller')
    lock = json.loads(Path('security/verifier-vex.lock.json').read_text())
    report = json.loads((a/'scan.json').read_text())
    source = json.loads((a/'source.json').read_text())
    packages = (a/'packages.txt').read_text().splitlines()
    filtered, finding = evaluate(report, (a/'openpgp-advisory.json').read_bytes(), packages, source, lock)
    # The archive/config gate must run before this program. The source record and
    # package closure come from the same locked build that generated that binary.
    subject = source['manifestDigest']
    manifest = json.loads((a/'build-metadata.json').read_text())
    assert subject == manifest['containerimage.digest']
    assert report['Metadata']['ImageID'] == manifest['containerimage.config.digest']
    product = 'urn:sha256:' + subject.removeprefix('sha256:')
    vex = {'@context': 'https://openvex.dev/ns/v0.2.0',
           'author': 'https://github.com/jayekwere',
           'role': 'DocumentCreator', 'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'version': 1,
           'statements': [{'vulnerability': {'@id': lock['url'], 'name': lock['id']},
                           'products': [{'@id': product}], 'status': 'not_affected',
                           'justification': 'vulnerable_code_not_present',
                           'impact_statement': 'The advisory affects only the OpenPGP package family. The complete target-specific Go package closure for this statically built verifier excludes that family. The module remains in the raw inventory; no other finding is suppressed.'}]}
    vex['@id'] = 'urn:sha256:' + hashlib.sha256(json.dumps(vex,sort_keys=True).encode()).hexdigest()
    (a/'vex.json').write_text(json.dumps(vex, indent=2)+'\n')
    (a/'scan-policy-input.json').write_text(json.dumps(filtered, indent=2)+'\n')
    (a/'vex-evidence.json').write_text(json.dumps({'schemaVersion': 1, 'manifestDigest': subject,
        'binarySHA256': source['binarySHA256'], 'architecture': source['architecture'],
        'advisorySHA256': lock['sha256'], 'packageClosureSHA256': hashlib.sha256((a/'packages.txt').read_bytes()).hexdigest(),
        'compiledPackageCount': len(packages), 'affectedPackagePaths': json.loads((a/'openpgp-advisory.json').read_text())['affected'][0]['ecosystem_specific']['imports'],
        'finding': finding}, indent=2)+'\n')
    print('PASS bounded VEX: affected OpenPGP packages absent from compiled closure; raw finding retained')
