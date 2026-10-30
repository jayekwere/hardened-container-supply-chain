#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
mkdir -p artifacts/controller .cache/controller-mod .cache/controller-go
source_dir=$(python3 scripts/prepare-controller.py)
sdk=$(python3 -c 'import json;print(json.load(open("integration/admission/inputs.lock.json"))["controller"]["buildImage"])')
arch=$(docker version --format '{{.Server.Arch}}')
target=${CONTROLLER_ARCH:-$arch}
case "$target" in amd64|arm64) ;; *) exit 1 ;; esac
docker run --rm \
  -v "$source_dir:/src" -v "$PWD/.cache/controller-mod:/gomod" \
  -v "$PWD/.cache/controller-go:/gocache" -v "$PWD/artifacts/controller:/out" \
  -w /src -e GOTOOLCHAIN=local -e GOPROXY=https://proxy.golang.org \
  -e GOSUMDB=sum.golang.org -e GOMODCACHE=/gomod -e GOCACHE=/gocache \
  -e CGO_ENABLED=0 -e GOMAXPROCS=2 -e GOFLAGS=-p=2 -e TARGETARCH="$target" \
  -e REPRODUCE="${CONTROLLER_REPRODUCE:-0}" \
  "$sdk" sh -eu -c '
    test "$(go env GOVERSION)" = go1.27.3
    test -z "$(gofmt -l pkg/webhook/freshness.go pkg/webhook/freshness_test.go)"
    go test -mod=readonly -count=1 -v ./pkg/webhook -run "^TestPolicyFreshness" > /out/unit-tests.txt 2>&1
    # Exercise the upgraded dependencies through their own security regressions
    # and ordinary parse/round-trip controls, including HTML absent from this binary.
    go test -mod=readonly -count=1 -v github.com/go-jose/go-jose/v4 -run "^(TestRsaKeyChecks|TestEmbeddedPrivateJWKRejected|TestPrivateEPKRejected|TestUnmarshalPrivateJWKAllowed|TestRoundtripRsaPrivate)$" >> /out/unit-tests.txt 2>&1
    go test -mod=readonly -count=1 -v golang.org/x/net/html -run "^(TestTextNodeCoalescing|TestRenderFosteredForeignContent|TestRenderer)$" >> /out/unit-tests.txt 2>&1
    go mod verify > /out/modules.txt
    GOOS=linux GOARCH="$TARGETARCH" go list -mod=readonly -deps -f "{{.ImportPath}}" ./cmd/webhook > /tmp/packages.txt
    sort /tmp/packages.txt > /out/packages.txt
    GOOS=linux GOARCH="$TARGETARCH" go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/webhook ./cmd/webhook
    if [ "$REPRODUCE" = 1 ]; then
      GOOS=linux GOARCH="$TARGETARCH" go build -a -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /tmp/webhook-second ./cmd/webhook
      cmp /out/webhook /tmp/webhook-second
      printf "PASS independently recompiled verifier binary is byte-identical\n" > /out/reproducibility.txt
    else
      printf "SKIP independent verifier recompilation; enabled for release\n" > /out/reproducibility.txt
    fi
    cp LICENSE /out/LICENSE
    cp go.mod go.sum /out/
  '
builder="hsc-controller-build-$$"
trap 'docker buildx rm --force "$builder" >/dev/null 2>&1 || true' EXIT
docker buildx create --name "$builder" --driver docker-container --driver-opt image=moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f >/dev/null
docker buildx build --builder "$builder" --platform "linux/$target" --network=none \
  --provenance=false --sbom=false --build-arg SOURCE_DATE_EPOCH=0 \
  --metadata-file artifacts/controller/build-metadata.json \
  --output=type=docker,dest=artifacts/controller/image.tar,rewrite-timestamp=true \
  -t supply-policy-controller:local -f integration/admission/Controller.Dockerfile .
docker load -i artifacts/controller/image.tar
docker image inspect supply-policy-controller:local > artifacts/controller/image-inspect.json
python3 - <<'PY'
import hashlib, json
from pathlib import Path
a=Path('artifacts/controller')
i=json.loads((a/'image-inspect.json').read_text())[0]
assert i['Config']['User']=='1000:1000' and i['Config']['Entrypoint']==['/webhook']
lock=json.loads(Path('integration/admission/inputs.lock.json').read_text())['controller']
record={'sourceCommit':lock['sourceCommit'],'sourceArchiveSHA256':lock['sourceArchive']['sha256'],
        'patchSHA256':hashlib.sha256(Path('patches/policy-controller-freshness.patch').read_bytes()).hexdigest(),
        'dependencyPatchSHA256':hashlib.sha256(Path('patches/policy-controller-dependencies.patch').read_bytes()).hexdigest(),
        'goModSHA256':hashlib.sha256((a/'go.mod').read_bytes()).hexdigest(),
        'goSumSHA256':hashlib.sha256((a/'go.sum').read_bytes()).hexdigest(),
        'packageClosureSHA256':hashlib.sha256((a/'packages.txt').read_bytes()).hexdigest(),
        'binarySHA256':hashlib.sha256((a/'webhook').read_bytes()).hexdigest(),
        'buildImage':lock['buildImage'],'architecture':i['Architecture'],
        'manifestDigest':json.loads((a/'build-metadata.json').read_text())['containerimage.digest']}
(a/'source.json').write_text(json.dumps(record,indent=2)+'\n')
print('PASS patched controller built; source, modules and focused tests verified')
PY
