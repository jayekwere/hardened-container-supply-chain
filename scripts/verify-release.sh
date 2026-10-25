#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
image=${1:?usage: verify-release.sh IMAGE@sha256:DIGEST vMAJOR.MINOR.PATCH}
tag=${2:?release tag required}
[[ "$image" =~ ^ghcr.io/jayekwere/hardened-container-supply-chain@sha256:[a-f0-9]{64}$ ]]
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
identity="https://github.com/jayekwere/hardened-container-supply-chain/.github/workflows/release.yml@refs/tags/$tag"
issuer=https://token.actions.githubusercontent.com
mkdir -p artifacts
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$image" > artifacts/verified-signature.json
cosign verify-attestation --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --type cyclonedx "$image" > artifacts/verified-sbom-attestation.jsonl
cosign verify-attestation --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --type 'https://github.com/jayekwere/hardened-container-supply-chain/evidence/v1' "$image" > artifacts/verified-evidence-attestation.jsonl
printf 'PASS image and attestations match exact release identity\n'
