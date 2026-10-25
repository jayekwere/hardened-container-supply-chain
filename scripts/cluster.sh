#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
name="hsc-$$"
kubeconfig="$PWD/.tools/kubeconfig-$name"
cleanup() { kind delete cluster --name "$name"; rm -f "$kubeconfig"; }
trap cleanup EXIT
# Use the engine's native architecture for the disposable cluster.
arch=$(docker version --format '{{.Server.Arch}}')
ARTIFACT_DIR=artifacts/cluster IMAGE=supply-demo:cluster PLATFORM="linux/$arch" ./scripts/build.sh
kind create cluster --name "$name" --kubeconfig "$kubeconfig" --image kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a --wait 120s
kind load docker-image supply-demo:cluster --name "$name"
node="$name-control-plane"
repo=docker.io/library/supply-demo
digest=$(docker exec "$node" ctr --namespace=k8s.io images ls | awk '$1=="docker.io/library/supply-demo:cluster" {print $3}')
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
docker exec "$node" ctr --namespace=k8s.io images tag "$repo:cluster" "$repo@$digest"
kubectl --kubeconfig "$kubeconfig" create namespace supply-demo
kubectl --kubeconfig "$kubeconfig" label namespace supply-demo pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=v1.34
helm install demo charts/supply-demo --kubeconfig "$kubeconfig" --namespace supply-demo --set "image.repository=$repo" --set "image.digest=$digest" --wait --timeout 120s
TEST_KUBECONFIG="$kubeconfig" go test -tags=kubernetes -count=1 -v ./integration | tee artifacts/cluster/tests.txt
