#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
artifact_dir=${ARTIFACT_DIR:-artifacts}
mkdir -p "$artifact_dir"
image=${IMAGE:-supply-demo:local}
platform=${PLATFORM:-linux/amd64}
builder="hsc-build-$$"
trap 'docker buildx rm --force "$builder" >/dev/null 2>&1 || true' EXIT
docker buildx create --name "$builder" --driver docker-container --driver-opt image=moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f >/dev/null
docker buildx build --builder "$builder" --platform "$platform" --network=none --no-cache --provenance=false --sbom=false --build-arg SOURCE_DATE_EPOCH=0 --metadata-file "$artifact_dir/build-metadata.json" --output="type=docker,dest=$artifact_dir/image.tar,rewrite-timestamp=true" -t "$image" .
python3 scripts/check-image.py "$artifact_dir" > "$artifact_dir/config-digest.txt"
docker load -i "$artifact_dir/image.tar"
docker image inspect "$image" > "$artifact_dir/image-inspect.json"
