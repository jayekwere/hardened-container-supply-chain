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
docker save supply-demo:local -o artifacts/image.tar
