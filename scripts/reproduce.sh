#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE=supply-demo:repro-a ./scripts/build.sh
first=$(python3 -c 'import json;print(json.load(open("artifacts/build-metadata.json"))["containerimage.digest"])')
IMAGE=supply-demo:repro-b ./scripts/build.sh
second=$(python3 -c 'import json;print(json.load(open("artifacts/build-metadata.json"))["containerimage.digest"])')
test "$first" = "$second"
printf 'PASS two uncached builds: image config and layer digests match %s\n' "$first" | tee artifacts/reproducibility.txt
# Keep the tested image as the single local input for later checks.
docker tag supply-demo:repro-b supply-demo:local
copydir=$(mktemp -d "$PWD/artifacts/oci-copy.XXXXXX")
trap 'rm -rf "$copydir"' EXIT
.tools/bin/oras cp --from-oci-layout --to-oci-layout "artifacts/image.tar@$second" "$copydir:verified"
copied=$(.tools/bin/oras resolve --oci-layout "$copydir:verified")
test "$copied" = "$second"
printf 'PASS OCI transfer preserves gated manifest digest\n' | tee -a artifacts/reproducibility.txt
