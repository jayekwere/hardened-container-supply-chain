#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
image=${1:?}; tag=${2:?}
./scripts/verify-controller-release.sh "$image" "$tag" artifacts/controller
wrong_identity="https://github.com/jayekwere/hardened-container-supply-chain/.github/workflows/controller-release.yml@refs/tags/controller-v0.0.0"
if cosign verify --certificate-identity "$wrong_identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image" > artifacts/controller/wrong-identity.txt 2>&1; then
  echo 'FAIL wrong release identity admitted'; exit 1
fi
python3 - <<'PY'
from pathlib import Path
s=Path('artifacts/controller/wrong-identity.txt').read_text().lower()
assert 'identit' in s and 'match' in s, 'wrong-identity failure must identify the identity mismatch'
PY
python3 - "$image" "$(git rev-parse "$tag^{commit}")" <<'PY'
import json, shutil, subprocess, sys, tempfile
from pathlib import Path
a=Path('artifacts/controller')
with tempfile.TemporaryDirectory() as temp:
    p=Path(temp)
    for n in list(json.loads((a/'release-evidence.json').read_text())['checksums'])+['release-evidence.json']:
        shutil.copyfile(a/n,p/n)
    with (p/'sbom.cdx.json').open('a') as f: f.write('\n')
    r=subprocess.run([sys.executable,'scripts/verify-controller-predicates.py',sys.argv[1],sys.argv[2],temp],capture_output=True,text=True)
    assert r.returncode!=0 and 'DENY no matching signed' in r.stderr
    (a/'tampered-report.txt').write_text(r.stdout+r.stderr)
(a/'release-tests.json').write_text(json.dumps({'schemaVersion':1,'image':sys.argv[1],'positiveSignatureAndBothAttestations':'passed','wrongWorkflowIdentity':'rejected','changedSBOMReportBytes':'rejected'},indent=2)+'\n')
print('PASS exact release verified; wrong identity and changed report rejected')
PY
