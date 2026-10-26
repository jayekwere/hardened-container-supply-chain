#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
image=${1:?digest-addressed verifier image required}
tag=${2:?controller-vMAJOR.MINOR.PATCH required}
[[ "$image" =~ ^ghcr.io/jayekwere/hardened-container-supply-chain@sha256:[a-f0-9]{64}$ ]]
[[ "$tag" =~ ^controller-v[0-9]+\.[0-9]+\.[0-9]+$ ]]
identity="https://github.com/jayekwere/hardened-container-supply-chain/.github/workflows/controller-release.yml@refs/tags/$tag"
revision=$(git rev-parse "$tag^{commit}")
mkdir -p artifacts/controller
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image" > artifacts/controller/verified-signature.json
cosign verify-attestation --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com --type cyclonedx "$image" > artifacts/controller/verified-sbom-attestation.jsonl
cosign verify-attestation --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com --type 'https://github.com/jayekwere/hardened-container-supply-chain/verifier-evidence/v1' "$image" > artifacts/controller/verified-evidence-attestation.jsonl
python3 scripts/verify-controller-predicates.py "$image" "$revision" "${3:-}"
