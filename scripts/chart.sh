#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
mkdir -p artifacts bin
go build -mod=readonly -o bin/policy ./cmd/policy
helm lint charts/supply-demo -f examples/pass-values.yaml
helm template demo charts/supply-demo -f examples/pass-values.yaml > artifacts/manifests.json.yaml
bin/policy manifests --file artifacts/manifests.json.yaml
helm template demo charts/supply-demo -f examples/fail-values.yaml > artifacts/unsafe.json.yaml
set +e
bin/policy manifests --file artifacts/unsafe.json.yaml > artifacts/unsafe-policy.txt
code=$?
set -e
test "$code" -eq 1
grep -q 'DENY K8S-READONLY' artifacts/unsafe-policy.txt
cat artifacts/unsafe-policy.txt
printf 'PASS intentionally unsafe chart rejected (exit 1)\n'
