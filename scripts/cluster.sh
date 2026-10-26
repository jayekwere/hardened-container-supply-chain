#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
name="hsc-$$"
kubeconfig="$PWD/.tools/kubeconfig-$name"
cleanup() {
  code=$?
  if [ "$code" -ne 0 ] && [ -f "$kubeconfig" ]; then
    kubectl --kubeconfig "$kubeconfig" get pods -A -o wide > artifacts/cluster/failure-pods.txt 2>&1 || true
    kubectl --kubeconfig "$kubeconfig" -n kube-system logs -l app=kube-network-policies --all-containers --prefix --tail=100 > artifacts/cluster/failure-enforcer.txt 2>&1 || true
  fi
  kind delete cluster --name "$name" || code=1
  rm -f "$kubeconfig"
  exit "$code"
}
trap cleanup EXIT
# Use the engine's native architecture for the disposable cluster.
arch=$(docker version --format '{{.Server.Arch}}')
ARTIFACT_DIR=artifacts/cluster IMAGE=supply-demo:cluster PLATFORM="linux/$arch" ./scripts/build.sh
kind create cluster --config integration/network-policy/kind.yaml --name "$name" --kubeconfig "$kubeconfig" --image kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a --wait 120s
kubectl --kubeconfig "$kubeconfig" apply -f integration/network-policy/enforcer.json
kubectl --kubeconfig "$kubeconfig" -n kube-system rollout status daemonset/kube-network-policies --timeout=120s
kubectl --kubeconfig "$kubeconfig" -n kube-system rollout status deployment/coredns --timeout=120s
kubectl --kubeconfig "$kubeconfig" get nodes -o json > artifacts/cluster/nodes.json
kubectl --kubeconfig "$kubeconfig" -n kube-system get daemonset kube-network-policies -o json > artifacts/cluster/enforcer.json
kind load docker-image supply-demo:cluster --name "$name"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOTOOLCHAIN=local go build -mod=readonly -trimpath -buildvcs=false -o artifacts/cluster/netprobe ./integration/netprobe
node="$name-control-plane"
repo=docker.io/library/supply-demo
digest=$(docker exec "$node" ctr --namespace=k8s.io images ls | awk '$1=="docker.io/library/supply-demo:cluster" {print $3}')
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
for test_node in $(kind get nodes --name "$name"); do
  imported=$(docker exec "$test_node" ctr --namespace=k8s.io images ls | awk '$1=="docker.io/library/supply-demo:cluster" {print $3}')
  test "$imported" = "$digest"
  docker exec "$test_node" ctr --namespace=k8s.io images tag --force "$repo:cluster" "$repo@$digest"
  docker cp artifacts/cluster/netprobe "$test_node:/hsc-netprobe"
done
kubectl --kubeconfig "$kubeconfig" create namespace supply-demo
kubectl --kubeconfig "$kubeconfig" label namespace supply-demo pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=v1.34
helm install demo charts/supply-demo --kubeconfig "$kubeconfig" --namespace supply-demo --set "image.repository=$repo" --set "image.digest=$digest" --wait --timeout 120s
TEST_KIND_NAME="$name" TEST_KUBECONFIG="$kubeconfig" go test -tags=kubernetes -count=1 -v ./integration | tee artifacts/cluster/tests.txt
