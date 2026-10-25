# hardened-container-supply-chain

A working container supply chain for a tiny Go HTTP service: build a scratch image, test its runtime restrictions, render and gate a Helm deployment, inventory and scan the exact image, then publish and verify a signed release by digest.

The application is intentionally small so the controls can be inspected end to end. It serves `GET /healthz`, `/readyz`, and `/version` on port 8080, needs no credentials, writes no application data, and makes no outbound requests.

## Verified status

See [verification evidence](docs/verification.md) for dated local results and hosted workflow results. The initial live scan found vulnerable standard-library code; [remediation evidence](docs/remediation.md) records the compiler upgrade and rescan. Synthetic negative fixtures are clearly marked and are never presented as real findings. There are no active exceptions and no VEX assertions.

## Run the complete checks

Requirements: a Unix shell, Make, Python 3.12+, a C compiler for Go's race detector, and a running OCI-compatible local engine with `docker buildx` and timestamp rewriting support (BuildKit 0.13+). Internet access is required for locked tool downloads, the pinned builder image, and a vulnerability database updated within 24 hours. Linux amd64 and macOS arm64 tool installations are locked in `tools.lock.json`.

```sh
git clone https://github.com/jayekwere/hardened-container-supply-chain.git
cd hardened-container-supply-chain
make tools
make check
./scripts/sign-local.sh
make cluster
```

`make check` runs formatting and dependency checks, vet, race-enabled Go tests, chart lint and both policy examples, two uncached image builds, Go container integration tests, a fresh vulnerability scan, and CycloneDX SBOM generation. `make cluster` creates its own cluster and private kubeconfig, installs the real chart by digest, runs Go integration tests, and deletes that cluster. It never selects an existing cluster.

| Command | Result required |
| --- | --- |
| `make test` | Exact compiler, no external modules, vet and race tests pass |
| `make chart` | Hardened render passes; writable-root render exits 1 |
| `make reproduce` | Two uncached builds produce the same manifest digest |
| `make integration` | HTTP responds; UID/GID, read-only root, zero capabilities and no-new-privileges verified; shell absent |
| `make scan` | Versioned standard-library inventory, matching config digest, fresh database, no blocking findings |
| `./scripts/sign-local.sh` | Ephemeral-key SBOM signature verifies; changed bytes fail |
| `make cluster` | Service works; process restrictions hold; privileged pod is denied by restricted admission |

Individual commands reuse `artifacts/` from prior commands. Run `make tools` first, and build before running image-dependent checks. The local signature exercise deliberately disables transparency-log use; the release workflow requires identity certificates and normal transparency verification.

## Try passing and failing policies

```sh
# Generates the positive and negative renders and checks exact exit behavior:
make chart
cat artifacts/unsafe-policy.txt
# DENY K8S-READONLY

# Inspect the negative render directly; exit 1 is expected:
bin/policy manifests --file artifacts/unsafe.json.yaml
```

`examples/pass-values.yaml` uses an all-zero digest solely to render a fixture. It is not a deployable release. The policy accepts the chart's JSON-as-YAML documents and deliberately rejects arbitrary resource kinds, missing resources, mutable image references, root users, writable roots, privilege escalation, extra containers and mounts, token mounts, and altered network-policy selectors/rules. It is scoped to this chart, not a general Kubernetes admission engine.

The scanner fixtures in `internal/policy/testdata/scan-*.json` contain synthetic data. To observe the HIGH gate's failure without a live vulnerability:

```sh
bin/policy scan --file internal/policy/testdata/scan-high.json \
  --image-id sha256:1111111111111111111111111111111111111111111111111111111111111111 \
  --subject sha256:1111111111111111111111111111111111111111111111111111111111111111
# DENY HIGH:CVE-2099-0001|stdlib|v0.0.0-synthetic
# exit 1
```

Policy CLI exit codes: `0` pass, `1` denied, `2` invalid input or execution error. [Regression tests](internal/policy/scan_test.go) cover valid scoped exceptions, expiry, future dates, overlong lifetimes, digest/version mismatch, missing evidence, duplicate/unused entries, unknown severity and critical findings.

## Run the image

```sh
make image
docker run --rm --platform linux/amd64 --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 32 --memory 64m --cpus 0.5 \
  -p 127.0.0.1:8080:8080 supply-demo:local
# In a second terminal:
curl --fail http://127.0.0.1:8080/healthz
```

The image contains one statically linked executable, owned by UID/GID 65532; it contains no shell, package manager, OS packages, or certificate bundle. The archive gate checks the binary's ELF architecture against the image architecture. Read-only filesystem and privilege restrictions are runtime settings; the chart and integration commands set them explicitly.

## Verify and deploy a release

Release tags must have the form `vMAJOR.MINOR.PATCH` and point to a commit reachable from `main`. After the quality workflow passes, the release workflow rebuilds and rescans, publishes the exact manifest, signs it with the release workflow's short-lived identity, attaches signed SBOM and evidence predicates, and verifies all three before recording a release. No long-lived signing secret is configured.

Take the exact reference from the release's `image-reference.txt` asset. Do not substitute a mutable tag or the local image config digest.

```sh
export IMAGE='ghcr.io/jayekwere/hardened-container-supply-chain@sha256:REPLACE_WITH_RELEASE_DIGEST'
export TAG='v0.1.0'
./scripts/verify-release.sh "$IMAGE" "$TAG"

export PATH="$PWD/.tools/bin:$PATH"
DIGEST="${IMAGE##*@}"
helm template demo charts/supply-demo --set "image.digest=$DIGEST" > artifacts/deploy.json.yaml
bin/policy manifests --file artifacts/deploy.json.yaml
kubectl create namespace supply-demo
kubectl label namespace supply-demo pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.34
helm install demo charts/supply-demo --namespace supply-demo --set "image.digest=$DIGEST" --wait
kubectl -n supply-demo port-forward service/demo 8080:8080
```

These deployment commands target your selected cluster and assume Kubernetes 1.34, pull access to the image, and a network plugin that enforces NetworkPolicy. The chart supports Kubernetes 1.30+; the pinned integration environment tests 1.34. The network policy permits only namespace-local ingress to TCP 8080 and denies all pod egress, including DNS. The service needs neither DNS nor external connectivity.

Verification is an explicit pre-deployment command. The chart does not install an admission webhook and Kubernetes does not automatically verify the image signature. Configure an admission verifier separately if continuous enforcement is required. For rollback, verify a previous release's digest and run `helm upgrade` with that digest.

## Evidence and design

- [Architecture and trust boundaries](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Security decisions and dependency updates](docs/security-decisions.md)
- [Remediation and exception process](docs/remediation.md)
- [Release evidence format and permissions](docs/release-evidence.md)
- [Exact verification results and operational limits](docs/verification.md)

SBOMs, raw scans, database metadata, reproducibility output and test results are generated under ignored `artifacts/`. Hosted runs retain evidence for 14 days; tagged release runs retain it for 90 days and publish the final evidence as release assets. Scan evidence is a point-in-time package assessment, not a claim that the service has no vulnerabilities.

## License

MIT. See [LICENSE](LICENSE).
