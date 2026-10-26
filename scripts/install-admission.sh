#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
kubeconfig=${1:?explicit kubeconfig required}
python3 - <<'PY'
import hashlib,json,urllib.request
from pathlib import Path
lock=json.loads(Path('integration/admission/inputs.lock.json').read_text())['chart']
path=Path('.tools/charts/policy-controller-'+lock['version']+'.tgz')
path.parent.mkdir(parents=True,exist_ok=True)
if not path.exists(): path.write_bytes(urllib.request.urlopen(lock['url'],timeout=90).read())
if hashlib.sha256(path.read_bytes()).hexdigest()!=lock['sha256']: raise SystemExit('DENY admission chart checksum mismatch')
print('PASS admission chart checksum')
PY
kubectl --kubeconfig "$kubeconfig" create namespace image-policy-system
kubectl --kubeconfig "$kubeconfig" label namespace image-policy-system pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=v1.34
helm install policy-controller .tools/charts/policy-controller-0.10.8.tgz --kubeconfig "$kubeconfig" --namespace image-policy-system --values integration/admission/controller-values.json --wait --timeout 180s --no-hooks
kubectl --kubeconfig "$kubeconfig" apply -f integration/admission/release-policy.json
