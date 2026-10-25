#!/usr/bin/env python3
import datetime, json
from pathlib import Path
raw = Path('.cache/trivy/db/metadata.json').read_text()
metadata = json.loads(raw)
updated = datetime.datetime.fromisoformat(metadata['UpdatedAt'].replace('Z', '+00:00'))
now = datetime.datetime.now(datetime.timezone.utc)
if not datetime.timedelta(0) <= now - updated <= datetime.timedelta(hours=24):
    raise SystemExit('DENY vulnerability database must be updated within 24 hours')
Path('artifacts/db-metadata.json').write_text(raw)
print('PASS vulnerability database freshness')
