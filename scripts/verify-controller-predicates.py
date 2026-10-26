#!/usr/bin/env python3
"""Validate already signature-verified DSSE claims and optional downloaded reports."""
import base64, hashlib, json, re, sys
from pathlib import Path

def validate(sbom, evidence, image, revision, directory=None):
    digest=image.split('@sha256:')[1]
    for statement, kind in [(sbom,'https://cyclonedx.org/bom'),(evidence,'https://github.com/jayekwere/hardened-container-supply-chain/verifier-evidence/v1')]:
        assert statement['_type']=='https://in-toto.io/Statement/v0.1'
        assert statement['predicateType']==kind
        assert any(s.get('digest',{}).get('sha256')==digest for s in statement['subject'])
    s,e=sbom['predicate'],evidence['predicate']
    assert s['bomFormat']=='CycloneDX' and s['specVersion']=='1.7'
    assert any(c.get('name')=='stdlib' and c.get('version')=='v1.27.3' for c in s['components'])
    assert len(s['components'])>100
    assert e['schemaVersion']==1 and e['image']==image and e['sourceRevision']==revision
    assert e['builder']=='controller-release.yml' and e['platform']=='linux/amd64'
    assert e['exceptions']=={'schemaVersion':1,'entries':[]}
    lock=json.loads(Path('integration/admission/inputs.lock.json').read_text())['controller']
    assert e['upstream']['sourceCommit']==lock['sourceCommit']
    assert e['upstream']['sourceArchiveSHA256']==lock['sourceArchive']['sha256']
    assert e['upstream']['buildImage']==lock['buildImage']
    assert e['upstream']['architecture']=='amd64'
    assert e['upstream']['patchSHA256']==hashlib.sha256(Path('patches/policy-controller-freshness.patch').read_bytes()).hexdigest()
    assert e['upstream']['dependencyPatchSHA256']==hashlib.sha256(Path('patches/policy-controller-dependencies.patch').read_bytes()).hexdigest()
    assert e['upstream']['manifestDigest']=='sha256:'+digest
    assert e['vexProfile']==json.loads(Path('security/verifier-vex.lock.json').read_text())
    names={'scan.json','sbom.cdx.json','db-metadata.json','scanner-version.txt','source.json','modules.txt','unit-tests.txt','go.mod','go.sum','reproducibility.txt','packages.txt','vex.json','vex-evidence.json','openpgp-advisory.json','scan-policy-input.json'}
    assert set(e['checksums'])==names
    assert all(re.fullmatch('[a-f0-9]{64}',v) for v in e['checksums'].values())
    assert e['upstream']['goModSHA256']==e['checksums']['go.mod']
    assert e['upstream']['goSumSHA256']==e['checksums']['go.sum']
    assert e['upstream']['packageClosureSHA256']==e['checksums']['packages.txt']
    if directory:
        for name,expected in e['checksums'].items():
            assert hashlib.sha256((Path(directory)/name).read_bytes()).hexdigest()==expected, name
        assert json.loads((Path(directory)/'sbom.cdx.json').read_text())==s
        assert json.loads((Path(directory)/'release-evidence.json').read_text())==e

def statements(path):
    return [json.loads(base64.b64decode(json.loads(line)['payload'])) for line in Path(path).read_text().splitlines() if line.strip()]

if __name__=='__main__':
    a=Path('artifacts/controller')
    sboms=statements(a/'verified-sbom-attestation.jsonl');evidences=statements(a/'verified-evidence-attestation.jsonl')
    valid=False
    for s in sboms:
        for e in evidences:
            try: validate(s,e,sys.argv[1],sys.argv[2],sys.argv[3] if len(sys.argv)>3 else None)
            except (AssertionError,KeyError,ValueError): continue
            valid=True
    assert valid, 'DENY no matching signed SBOM/evidence claims or report hashes'
    print('PASS signed verifier claims and supplied evidence hashes')
