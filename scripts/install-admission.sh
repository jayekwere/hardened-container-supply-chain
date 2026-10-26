#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
kubeconfig=${1:?explicit kubeconfig required}
controller_image=${2:?explicit patched controller image digest required; run make controller-image and copy its archive to your registry}
[[ "$controller_image" =~ ^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$ ]]
python3 scripts/fetch-admission-chart.py
kubectl --kubeconfig "$kubeconfig" create namespace image-policy-system
kubectl --kubeconfig "$kubeconfig" label namespace image-policy-system pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=v1.34
helm install policy-controller .tools/charts/policy-controller-0.10.8.tgz --kubeconfig "$kubeconfig" --namespace image-policy-system --values integration/admission/controller-values.json --set "webhook.image.repository=${controller_image%@*}" --set "webhook.image.version=${controller_image##*@}" --wait --timeout 180s --no-hooks
kubectl --kubeconfig "$kubeconfig" apply -f integration/admission/release-policy.json
kubectl --kubeconfig "$kubeconfig" apply -f integration/admission/attestations-policy.json
