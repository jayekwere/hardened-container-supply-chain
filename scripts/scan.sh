#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
mkdir -p artifacts bin
# Explicitly update; stale/offline database use is never a release fallback.
trivy --cache-dir .cache/trivy image --download-db-only
python3 scripts/check-db.py
trivy --version > artifacts/scanner-version.txt
trivy --cache-dir .cache/trivy image --input artifacts/image.tar --skip-db-update --scanners vuln --ignorefile /dev/null --list-all-pkgs --format json --output artifacts/scan.json
trivy convert --format cyclonedx --output artifacts/sbom.cdx.json artifacts/scan.json
python3 - <<'CHECK'
import json
from pathlib import Path
sbom = json.loads(Path('artifacts/sbom.cdx.json').read_text())
assert sbom['bomFormat'] == 'CycloneDX'
expected = 'v' + json.loads(Path('tools.lock.json').read_text())['go']['version']
assert any(c.get('name') == 'stdlib' and c.get('version') == expected for c in sbom['components']), 'missing or unexpected Go standard library inventory'
print('PASS SBOM contains versioned stdlib')
CHECK
image_id=$(python3 scripts/check-image.py)
# Both local and release exceptions bind to the exported image manifest digest.
built_subject=$(python3 -c 'import json;print(json.load(open("artifacts/build-metadata.json"))["containerimage.digest"])')
subject=${SUBJECT_DIGEST:-$built_subject}
go build -mod=readonly -o bin/policy ./cmd/policy
bin/policy scan --file artifacts/scan.json --image-id "$image_id" --subject "$subject" | tee artifacts/scan-policy.txt
