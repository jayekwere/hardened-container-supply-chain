#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
name="hsc-admission-$$"
kubeconfig="$PWD/.tools/kubeconfig-$name"
mkdir -p artifacts/admission
cleanup() {
  code=$?
  if [ "$code" -ne 0 ] && [ -f "$kubeconfig" ]; then
    kubectl --kubeconfig "$kubeconfig" get pods -A -o wide > artifacts/admission/failure-pods.txt 2>&1 || true
    kubectl --kubeconfig "$kubeconfig" -n image-policy-system logs deployment/policy-controller-webhook --tail=150 > artifacts/admission/failure-controller.txt 2>&1 || true
  fi
  kind delete cluster --name "$name" || code=1
  docker rm -f "$name-registry" >/dev/null 2>&1 || true
  rm -rf "$PWD/.tools/attestation-fixtures-$name"
  rm -f "$kubeconfig"
  exit "$code"
}
trap cleanup EXIT
if [ -n "${TEST_RELEASE_CONTROLLER_IMAGE:-}" ]; then
  ./scripts/verify-controller-release.sh "$TEST_RELEASE_CONTROLLER_IMAGE" "${TEST_RELEASE_CONTROLLER_TAG:?}"
  controller_image=$TEST_RELEASE_CONTROLLER_IMAGE
else
  ./scripts/build-controller.sh
fi
kind create cluster --name "$name" --kubeconfig "$kubeconfig" --config integration/admission/kind-multi.yaml --image kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a --wait 180s
# This disposable cluster schedules the verifier on its control-plane nodes.
for node in $(kind get nodes --name "$name"); do
  kubectl --kubeconfig "$kubeconfig" patch node "$node" --type=merge -p '{"spec":{"taints":[]}}'
done
if [ -z "${TEST_RELEASE_CONTROLLER_IMAGE:-}" ]; then
  kind load docker-image supply-policy-controller:local --name "$name"
  controller_digest=$(docker exec "$name-control-plane" ctr --namespace=k8s.io images ls | awk '$1=="docker.io/library/supply-policy-controller:local" {print $3}')
  [[ "$controller_digest" =~ ^sha256:[a-f0-9]{64}$ ]]
  controller_image="docker.io/library/supply-policy-controller@$controller_digest"
  for node in $(kind get nodes --name "$name"); do
    docker exec "$node" ctr --namespace=k8s.io images tag --force docker.io/library/supply-policy-controller:local "$controller_image"
  done
fi
./scripts/install-admission.sh "$kubeconfig" "$controller_image"
python3 scripts/prepare-admission-fixtures.py "$kubeconfig" "$name"
kubectl --kubeconfig "$kubeconfig" get nodes -o json > artifacts/admission/nodes.json
kubectl --kubeconfig "$kubeconfig" -n image-policy-system get deployment policy-controller-webhook -o json > artifacts/admission/controller.json
# Resolve both manifests independently; an absent image is not evidence of signature rejection.
for field in signedImage unsignedImage; do
  image=$(python3 -c 'import json,sys;print(json.load(open("integration/admission/inputs.lock.json"))[sys.argv[1]])' "$field")
  oras resolve "$image" > "artifacts/admission/$field-digest.txt"
done
TEST_ADMISSION_KUBECONFIG="$kubeconfig" TEST_ADMISSION_KIND_NAME="$name" TEST_ADMISSION_CONTROLLER_IMAGE="$controller_image" TEST_ADMISSION_FIXTURES="$PWD/artifacts/admission/fixtures.json" go test -tags=admission -count=1 -timeout=15m -v ./integration | tee artifacts/admission/tests.txt
kubectl --kubeconfig "$kubeconfig" -n image-policy-system get pods -l app.kubernetes.io/instance=policy-controller -o json > artifacts/admission/controller-pods.json
if [ -n "${TEST_RELEASE_CONTROLLER_IMAGE:-}" ]; then
  python3 - "$controller_image" <<'PY'
import json,sys
pods=json.load(open('artifacts/admission/controller-pods.json'))['items']
running=[s for p in pods for s in p.get('status',{}).get('containerStatuses',[]) if s.get('state',{}).get('running')]
assert running and all(s['imageID'].endswith(sys.argv[1].split('@')[1]) for s in running), 'running verifier digest differs from published subject'
print('PASS running verifier manifest matches the scanned and signed registry subject')
PY
fi
