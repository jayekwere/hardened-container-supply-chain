#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
mkdir -p artifacts
keydir=$(mktemp -d)
trap 'rm -rf "$keydir"' EXIT
export COSIGN_PASSWORD=''
cosign generate-key-pair --output-key-prefix "$keydir/key"
cosign sign-blob --yes --key "$keydir/key.key" --tlog-upload=false --output-signature artifacts/local.sig artifacts/sbom.cdx.json
cp "$keydir/key.pub" artifacts/local.pub
cosign verify-blob --key artifacts/local.pub --signature artifacts/local.sig --insecure-ignore-tlog=true artifacts/sbom.cdx.json
cp artifacts/sbom.cdx.json artifacts/tampered-sbom.json
printf '\nTAMPERED\n' >> artifacts/tampered-sbom.json
if cosign verify-blob --key artifacts/local.pub --signature artifacts/local.sig --insecure-ignore-tlog=true artifacts/tampered-sbom.json > artifacts/tamper-rejection.txt 2>&1; then
  echo 'DENY tampering was accepted'; exit 1
fi
printf 'PASS local signature valid; tampered content rejected; ephemeral private key deleted\n' | tee artifacts/local-signing.txt
