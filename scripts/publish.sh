#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
: "${GITHUB_REF_NAME:?}" "${GITHUB_SHA:?}" "${GITHUB_TOKEN:?}" "${GITHUB_ACTOR:?}"
[[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
repo=ghcr.io/jayekwere/hardened-container-supply-chain
# Only commits reachable from the reviewed main branch may publish.
git merge-base --is-ancestor "$GITHUB_SHA" origin/main
make image integration
expected=$(python3 -c 'import json;print(json.load(open("artifacts/build-metadata.json"))["containerimage.digest"])')
SUBJECT_DIGEST="$expected" ./scripts/scan.sh
printf '%s' "$GITHUB_TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
trap 'docker logout ghcr.io >/dev/null 2>&1 || true' EXIT
oras cp --from-oci-layout "artifacts/image.tar@$expected" "$repo:$GITHUB_REF_NAME"
digest=$(docker buildx imagetools inspect "$repo:$GITHUB_REF_NAME" --format '{{.Manifest.Digest}}')
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
test "$digest" = "$expected"
printf '%s@%s\n' "$repo" "$digest" > artifacts/image-reference.txt
# Gate again with manifest-bound exceptions. Any failure leaves an UNSIGNED image.
SUBJECT_DIGEST="$digest" ./scripts/scan.sh
python3 scripts/evidence.py
cosign sign --yes "$repo@$digest"
cosign attest --yes --type cyclonedx --predicate artifacts/sbom.cdx.json "$repo@$digest"
cosign attest --yes --type 'https://github.com/jayekwere/hardened-container-supply-chain/evidence/v1' --predicate artifacts/release-evidence.json "$repo@$digest"
./scripts/verify-release.sh "$repo@$digest" "$GITHUB_REF_NAME"
helm package charts/supply-demo --destination artifacts --version "${GITHUB_REF_NAME#v}" --app-version "$GITHUB_REF_NAME"
(cd artifacts && sha256sum sbom.cdx.json scan.json release-evidence.json supply-demo-*.tgz > checksums.txt)
