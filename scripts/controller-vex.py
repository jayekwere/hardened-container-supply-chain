#!/usr/bin/env python3
"""Record a verified dependency fix without excluding any scanner finding."""
import copy
import datetime
import hashlib
import json
import sys
from pathlib import Path


def evaluate(report, advisory_bytes, packages, source, lock):
    assert lock['status'] == 'fixed' and lock['findingPolicy'] == 'unfiltered'
    assert hashlib.sha256(advisory_bytes).hexdigest() == lock['sha256'], 'reviewed advisory snapshot changed'
    advisory = json.loads(advisory_bytes)
    assert advisory['id'] == lock['id'] and not advisory.get('withdrawn')
    assert len(advisory['affected']) == 2
    prefix = lock['packagePrefix']
    assert prefix == lock['module'] + '/openpgp'
    affected = {item['package']['name']: item for item in advisory['affected']}
    assert set(affected) == {lock['module'], prefix}
    for module, item in affected.items():
        assert item['package'] == {'name': module, 'ecosystem': 'Go'}
        paths = [p['path'] for p in item['ecosystem_specific']['imports']]
        assert paths and all(p == prefix or p.startswith(prefix + '/') for p in paths)
    assert affected[lock['module']]['ranges'] == [{'type': 'SEMVER', 'events': [
        {'introduced': '0'}, {'fixed': lock['moduleVersion'].removeprefix('v')}]}]
    assert affected[prefix]['ranges'] == [{'type': 'SEMVER', 'events': [{'introduced': '0'}]}]
    assert len(packages) > 100 and len(packages) == len(set(packages))
    assert hashlib.sha256(('\n'.join(packages)+'\n').encode()).hexdigest() == source['packageClosureSHA256'], 'package closure differs from binary build record'
    assert 'github.com/sigstore/policy-controller/cmd/webhook' in packages
    assert any(p.startswith(lock['module'] + '/') for p in packages)
    assert not any(p == prefix or p.startswith(prefix + '/') for p in packages), 'affected package is compiled'
    assert source['architecture'] in ['amd64', 'arm64']
    assert report['Metadata']['ImageID'].startswith('sha256:')
    inventory = [p for result in report['Results'] if result['Type'] == 'gobinary'
                 for p in result.get('Packages', []) if p['Name'] == lock['module']]
    assert len(inventory) == 1 and inventory[0]['Version'] == lock['moduleVersion'], 'fixed module inventory differs'
    assert not any(p['Name'] == prefix or p['Name'].startswith(prefix + '/') for result in report['Results']
                   for p in result.get('Packages', [])), 'legacy OpenPGP module is present'
    assert not any(f['VulnerabilityID'] == lock['id'] for result in report['Results']
                   for f in result.get('Vulnerabilities') or []), 'advisory reappeared; review before recording a fix'
    return copy.deepcopy(report), inventory[0]


if __name__ == '__main__':
    a = Path('artifacts/controller')
    lock = json.loads(Path('security/verifier-vex.lock.json').read_text())
    raw_report = (a/'scan.json').read_bytes()
    report = json.loads(raw_report)
    source = json.loads((a/'source.json').read_text())
    packages = (a/'packages.txt').read_text().splitlines()
    unchanged, inventory = evaluate(report, (a/'openpgp-advisory.json').read_bytes(), packages, source, lock)
    assert unchanged == report
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
                           'products': [{'@id': product, 'subcomponents': [
                               {'@id': 'pkg:golang/' + lock['module'] + '@' + lock['moduleVersion']}]}],
                           'status': 'fixed',
                           'status_notes': 'The pinned parent module contains the upstream module-boundary fix. The separate legacy OpenPGP module and its packages are absent. This record excludes no scanner finding.'}]}
    vex['@id'] = 'urn:sha256:' + hashlib.sha256(json.dumps(vex,sort_keys=True).encode()).hexdigest()
    (a/'vex.json').write_text(json.dumps(vex, indent=2)+'\n')
    (a/'scan-policy-input.json').write_bytes(raw_report)
    (a/'vex-evidence.json').write_text(json.dumps({'schemaVersion': 1, 'manifestDigest': subject,
        'binarySHA256': source['binarySHA256'], 'architecture': source['architecture'],
        'advisorySHA256': lock['sha256'], 'packageClosureSHA256': hashlib.sha256((a/'packages.txt').read_bytes()).hexdigest(),
        'compiledPackageCount': len(packages), 'status': 'fixed', 'filteringApplied': False,
        'rawScanSHA256': hashlib.sha256(raw_report).hexdigest(),
        'policyInputSHA256': hashlib.sha256((a/'scan-policy-input.json').read_bytes()).hexdigest(),
        'moduleInventory': inventory}, indent=2)+'\n')
    print('PASS dependency fix recorded; legacy OpenPGP absent; every raw finding retained for the scan gate')
