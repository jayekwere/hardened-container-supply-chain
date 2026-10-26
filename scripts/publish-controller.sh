#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
: "${GITHUB_REF_NAME:?}" "${GITHUB_SHA:?}" "${GITHUB_TOKEN:?}" "${GITHUB_ACTOR:?}"
[[ "$GITHUB_REF_NAME" =~ ^controller-v[0-9]+\.[0-9]+\.[0-9]+$ ]]
git merge-base --is-ancestor "$GITHUB_SHA" origin/main
repo=ghcr.io/jayekwere/hardened-container-supply-chain
CONTROLLER_REPRODUCE=1 CONTROLLER_ARCH=amd64 ./scripts/build-controller.sh
./scripts/scan-controller.sh
expected=$(python3 -c 'import json;print(json.load(open("artifacts/controller/build-metadata.json"))["containerimage.digest"])')
printf '%s' "$GITHUB_TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
trap 'docker logout ghcr.io >/dev/null 2>&1 || true' EXIT
oras cp --from-oci-layout "artifacts/controller/image.tar@$expected" "$repo:$GITHUB_REF_NAME"
test "$(oras resolve "$repo:$GITHUB_REF_NAME")" = "$expected"
printf '%s@%s\n' "$repo" "$expected" > artifacts/controller/image-reference.txt
python3 scripts/controller-evidence.py
cosign sign --yes "$repo@$expected"
cosign attest --yes --type cyclonedx --predicate artifacts/controller/sbom.cdx.json "$repo@$expected"
cosign attest --yes --type 'https://github.com/jayekwere/hardened-container-supply-chain/verifier-evidence/v1' --predicate artifacts/controller/release-evidence.json "$repo@$expected"
./scripts/test-controller-release.sh "$repo@$expected" "$GITHUB_REF_NAME"
TEST_RELEASE_CONTROLLER_IMAGE="$repo@$expected" TEST_RELEASE_CONTROLLER_TAG="$GITHUB_REF_NAME" make admission
(cd artifacts/controller && sha256sum *.json *.txt go.mod go.sum > checksums.sha256)
