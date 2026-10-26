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
  rm -f "$kubeconfig"
  exit "$code"
}
trap cleanup EXIT
kind create cluster --name "$name" --kubeconfig "$kubeconfig" --image kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a --wait 120s
./scripts/install-admission.sh "$kubeconfig"
kubectl --kubeconfig "$kubeconfig" get nodes -o json > artifacts/admission/nodes.json
kubectl --kubeconfig "$kubeconfig" -n image-policy-system get deployment policy-controller-webhook -o json > artifacts/admission/controller.json
# Resolve both manifests independently; an absent image is not evidence of signature rejection.
for field in signedImage unsignedImage; do
  image=$(python3 -c 'import json,sys;print(json.load(open("integration/admission/inputs.lock.json"))[sys.argv[1]])' "$field")
  oras resolve "$image" > "artifacts/admission/$field-digest.txt"
done
TEST_ADMISSION_KUBECONFIG="$kubeconfig" TEST_ADMISSION_KIND_NAME="$name" go test -tags=admission -count=1 -v ./integration | tee artifacts/admission/tests.txt
