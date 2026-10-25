# Verification record

Observed on 2026-10-25. Results below were executed, not inferred from configuration. Local environment: macOS arm64, Linux arm64 engine, BuildKit 0.30.0, Go 1.27.3. Published-image tests target Linux amd64; the disposable cluster tests a native Linux arm64 build.

| Check | Exact local outcome |
| --- | --- |
| `make test` | Exit 0; exact compiler and zero external module checks, vet and race-enabled tests pass |
| Go package coverage | policy 99.3%; service library 47.1%; policy CLI 56.5%; service entrypoint 0.0% under unit coverage (binary exercised separately) |
| Archive regressions | 2 Python test methods pass, including 5 negative mutations: root, identity, architecture, ownership, extra file |
| `make chart` | Helm lint: 1 chart, 0 failed; hardened render exit 0; writable-root render exit 1 with `K8S-READONLY` |
| `make reproduce` | Exit 0; two uncached Linux amd64 builds have identical manifest digest listed below |
| `make integration` | 3 top-level Go tests pass; HTTP and kernel runtime diagnostics pass; all 3 deliberately unsafe runtime settings are rejected; `/bin/sh` absent |
| `make scan` | Exit 0; CycloneDX inventory contains stdlib v1.27.3; 0 findings; config identity and fresh DB checks pass; empty exception ledger |
| `scripts/sign-local.sh` | Exit 0; valid SBOM signature accepted; tampered bytes rejected; ephemeral private key deleted |
| `make cluster` | Exit 0; Helm deployment Ready in an isolated Kubernetes 1.34.0 cluster; all 3 Go subtests pass; cluster removed |
| Workflow checks | actionlint exit 0; pinned-action and permission regression guard exit 0 |

Linux amd64 manifest digest: `sha256:e0b4773135955a2d269f5f241771ede7c4fb3a47d37896af175aae8f8e7efe22`.

Linux amd64 config digest: `sha256:85d73d03e3d4fc8c92e9b143c753dd22fb699dfcda9c403b6c458beeb56ae4ce`.

Native cluster manifest digest: `sha256:a1fe6ec5772948818f8e52ddbfcb198865bb49fd4d68b36c1607a2feaaf88330`.

The live database reported `UpdatedAt: 2026-10-25T19:10:35.479132794Z`; the initial local download was `2026-10-25T23:34:17.50537Z`. See [baseline findings](evidence/baseline-findings.json) and [remediated findings](evidence/remediated-findings.json). Database content and future scan results are intentionally not frozen.

## Sample observed output

```text
PASS manifests
DENY K8S-READONLY
PASS intentionally unsafe chart rejected (exit 1)
PASS vulnerability database freshness
PASS SBOM contains versioned stdlib
PASS scan
runtime: uid=65532, rootfs=read-only, capabilities=0, no-new-privileges=1
/healthz: ok
/readyz: ready
/version: {"service":"supply-demo","api":1}
PASS restricted admission rejects privileged pod
PASS local signature valid; tampered content rejected; ephemeral private key deleted
```

## Hosted execution

The [first hosted quality run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40245866237) passed unit, archive and chart checks, then rejected an unsupported exporter on the runner's default builder. The build path now uses a digest-pinned disposable container builder. The corrected hosted run and keyless release are pending verification; local-key signing does not establish that hosted OIDC signing works.

## Operational limitations

- The default disposable-cluster CNI does not enforce NetworkPolicy. The rendered selectors/rules are checked, but no runtime traffic-denial result is claimed. Port-forwarding verifies service behavior and bypasses ordinary pod networking policy.
- Runtime seccomp is set to RuntimeDefault and accepted by the cluster; exact allowed/denied syscall behavior is platform-dependent and is not individually probed.
- Reproducibility is two uncached builds in one configured environment, not an independent cross-host rebuild. The host engine, runner image, Python, C compiler and other host tools are not all digest-pinned. BuildKit itself now uses a digest-pinned disposable container builder.
- Inventory and scanning cover discovered packages in the final image, including the Go standard library. They do not audit builder-image packages, pipeline-tool vulnerabilities, every application logic bug, or unknown vulnerabilities. Zero findings is a dated scanner result only.
- LOW/MEDIUM findings are visible but do not block. A high-severity risk acceptance is not an exploitability determination; no VEX is emitted.
- The chart has one replica, fixed small resources and no ingress, TLS, authentication or availability guarantees. CPU or memory pressure can make probes fail. Its diagnostics are for a small functional demonstration.
- Image verification is explicit; there is no installed signature-verifying admission controller. An administrator can bypass the CLI or alter workloads. Additional network policies can broaden effective access.
- Release publication can leave unsigned staged images if a later step fails. Only a completed release with successful signature and both attestation verifications is a supported deployment input.
- The registry may initially require authentication. Public source does not automatically grant anonymous package pulls. The release record and verification command still identify the exact digest.
- Hosted artifact retention is finite; final release assets preserve the principal evidence. Scheduled scanning depends on the hosted scheduler, repository activity and service availability; it is not a continuous runtime monitor.
