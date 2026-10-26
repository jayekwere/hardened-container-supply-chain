#!/usr/bin/env python3
import datetime, hashlib, json, os
from pathlib import Path

a=Path('artifacts/controller')
names=['scan.json','sbom.cdx.json','db-metadata.json','scanner-version.txt','source.json','modules.txt','unit-tests.txt','go.mod','go.sum','reproducibility.txt','packages.txt','vex.json','vex-evidence.json','openpgp-advisory.json','scan-policy-input.json']
assert (a/'reproducibility.txt').read_text().startswith('PASS independently recompiled')
evidence={'schemaVersion':1,'sourceRevision':os.environ['GITHUB_SHA'],
          'image':(a/'image-reference.txt').read_text().strip(),
          'generatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'builder':'controller-release.yml','platform':'linux/amd64',
          'vexProfile':json.loads(Path('security/verifier-vex.lock.json').read_text()),
          'upstream':json.loads((a/'source.json').read_text()),
          'checksums':{n:hashlib.sha256((a/n).read_bytes()).hexdigest() for n in names},
          'exceptions':json.loads(Path('security/exceptions.json').read_text())}
(a/'release-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
