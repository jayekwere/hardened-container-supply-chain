#!/usr/bin/env python3
import datetime, hashlib, json, os
from pathlib import Path
a = Path('artifacts')
names = ['scan.json', 'sbom.cdx.json', 'db-metadata.json', 'scanner-version.txt']
evidence = {'schemaVersion': 1, 'sourceRevision': os.environ['GITHUB_SHA'],
            'image': (a / 'image-reference.txt').read_text().strip(),
            'generatedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'checksums': {n: hashlib.sha256((a / n).read_bytes()).hexdigest() for n in names},
            'exceptions': json.loads(Path('security/exceptions.json').read_text()),
            'builder': 'release.yml', 'platform': 'linux/amd64'}
(a / 'release-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
