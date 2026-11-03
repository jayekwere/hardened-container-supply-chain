#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
python3 - <<'PY'
import json
assert json.load(open('security/exceptions.json')) == {'schemaVersion': 1, 'entries': []}, 'verifier release requires an empty exception ledger'
PY
trivy --cache-dir .cache/trivy image --download-db-only
python3 scripts/check-db.py
cp artifacts/db-metadata.json artifacts/controller/db-metadata.json
trivy --version > artifacts/controller/scanner-version.txt
trivy --cache-dir .cache/trivy image --input artifacts/controller/image.tar --skip-db-update --scanners vuln --ignorefile /dev/null --list-all-pkgs --format json --output artifacts/controller/scan.json
trivy convert --format cyclonedx --output artifacts/controller/sbom.cdx.json artifacts/controller/scan.json
image_id=$(python3 scripts/check-controller-image.py)
python3 - <<'PY'
import hashlib, json
from pathlib import Path
lock=json.loads(Path('security/verifier-vex.lock.json').read_text())
raw=Path(lock['advisoryPath']).read_bytes()
assert hashlib.sha256(raw).hexdigest()==lock['sha256'], 'reviewed advisory snapshot changed'
Path('artifacts/controller/openpgp-advisory.json').write_bytes(raw)
PY
python3 scripts/controller-vex.py
subject=$(python3 -c 'import json;print(json.load(open("artifacts/controller/build-metadata.json"))["containerimage.digest"])')
go build -mod=readonly -o bin/policy ./cmd/policy
bin/policy scan --file artifacts/controller/scan.json --image-id "$image_id" --subject "$subject" | tee artifacts/controller/scan-policy.txt
