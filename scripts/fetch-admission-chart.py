#!/usr/bin/env python3
import hashlib,json,urllib.request
from pathlib import Path
lock=json.loads(Path('integration/admission/inputs.lock.json').read_text())['chart']
path=Path('.tools/charts/policy-controller-'+lock['version']+'.tgz')
path.parent.mkdir(parents=True,exist_ok=True)
if not path.exists(): path.write_bytes(urllib.request.urlopen(lock['url'],timeout=90).read())
if hashlib.sha256(path.read_bytes()).hexdigest()!=lock['sha256']: raise SystemExit('DENY admission chart checksum mismatch')
print('PASS admission chart checksum')
