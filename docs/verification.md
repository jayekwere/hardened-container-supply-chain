# Verification record

Observed on 2026-10-25 (America/Vancouver). Results below were executed, not inferred from configuration. Local environment: macOS arm64, Linux arm64 engine, BuildKit 0.30.0, Go 1.27.3. Published-image tests target Linux amd64; the disposable cluster tests a native Linux arm64 build.

| Check | Exact local outcome |
| --- | --- |
| `make test` | Exit 0; exact compiler and zero external module checks, vet and race-enabled tests pass |
| Go package coverage | policy 99.3%; service library 47.1%; policy CLI 56.5%; service entrypoint 0.0% under unit coverage (binary exercised separately) |
| Archive regressions | 2 Python test methods pass, including 5 negative mutations: root, identity, architecture, ownership, extra file |
| `make chart` | Helm lint: 1 chart, 0 failed; hardened render exit 0; writable-root render exit 1 with `K8S-READONLY` |
| `make reproduce` | Exit 0; two uncached Linux amd64 builds have identical manifest digest listed below; OCI transfer regression preserves it |
| `make integration` | 3 top-level Go tests pass; HTTP and kernel runtime diagnostics pass; all 3 deliberately unsafe runtime settings are rejected; `/bin/sh` absent |
| `make scan` | Exit 0; CycloneDX inventory contains stdlib v1.27.3; 0 findings; config identity and fresh DB checks pass; empty exception ledger |
| `scripts/sign-local.sh` | Exit 0; valid SBOM signature accepted; tampered bytes rejected; ephemeral private key deleted |
| Initial `make cluster` | Exit 0; original single-node workload checks passed; superseded by the two-node traffic verification below |
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

The [final code quality run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40246809253) and [v0.1.1 release run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40246810683) both completed successfully for source commit `fbd97e985473537e99f47e8e987b6ade222e3bc6`. The release run's quality, publish and record jobs all passed. The hosted Linux amd64 builds also produced the same manifest and config digests observed locally.

[Release v0.1.1](https://github.com/jayekwere/hardened-container-supply-chain/releases/tag/v0.1.1) includes the packaged chart, raw scan, CycloneDX SBOM, database metadata, signed evidence predicate, checksums and verification output. Its published image is `ghcr.io/jayekwere/hardened-container-supply-chain@sha256:e0b4773135955a2d269f5f241771ede7c4fb3a47d37896af175aae8f8e7efe22`.

Additional consumer checks were executed after publication:

| Check | Outcome |
| --- | --- |
| `scripts/verify-release.sh IMAGE v0.1.1` | Exit 0; image, SBOM and evidence attestations validate with exact workflow identity, expected issuer and normal transparency checks |
| Wrong expected workflow identity | Cosign exit 12; explicit identity mismatch, not a network failure |
| Published asset checksums | All 4 entries match; all 4 signed evidence report hashes match downloaded assets |
| Signed evidence comparison | Verified attestation predicate equals downloaded release-evidence.json; subject matches the exact image digest |
| Published scan | 0 findings; no exceptions |
| Published image pull and Go runtime suite | Pull succeeds; all 3 top-level container tests and 3 unsafe-setting subtests pass |
| Packaged chart | Released 0.1.1 chart renders and passes manifest policy (exit 0) |
| Anonymous access | Registry manifest and signature/attestation reads succeed without package credentials |

See [structured release verification](evidence/release-verification.json).

The [first quality run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40245866237) stopped at an exporter unsupported by the runner's default builder. The digest-pinned disposable builder corrected that portability issue. The [v0.1.0 publishing attempt](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40246350655) then correctly stopped when an engine upload recompressed a layer and changed the manifest digest. It created no supported release. The successful path uses an OCI copy that preserves original compressed bytes, with a transfer regression and registry digest comparison. Use the completed v0.1.1 release; the earlier staged tag is not a verified deployment input.

## Runtime network-policy verification

The follow-up two-node run passed all 80 observed probes with zero expectation mismatches. Same-namespace ingress and unselected-peer controls remained reachable; cross-namespace ingress and workload HTTP/DNS egress timed out under policy. Removing the policy restored all 10 flows; reapplying it reproduced the results over three consecutive rounds. See [exact matrix and reproducible commands](network-policy.md) and [local evidence](evidence/network-policy-local.json). The [hosted quality run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40248892351) independently passed the same 80-probe matrix on two Linux amd64 nodes, also with zero mismatches; [hosted evidence](evidence/network-policy-hosted.json) records its exact counts and artifact hashes. Both environments retain the original application image digests.

## Admission-time signature enforcement

A pinned TLS admission verifier and exact release-identity policy are now available through `make admission` and the explicit-kubeconfig installer. The matrix covers signed/unsigned Pods and actual Helm Deployment templates, sidecars, init containers, ephemeral-container updates, wrong signer/issuer, no matching policy, namespace scope, verifier outage and recovery. See [methodology and exact results](admission-signatures.md). The final local suite passed all 16 admission cases in 16 API requests, plus 13 classification regressions, with runtime-confirmed verifier outage and successful recovery. The [hosted quality run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40252400191) passed the same 16 cases and 13 regressions in 17 requests: one temporary connection-refused result during recovery, followed by successful admission. All final decisions matched. Both [local evidence](evidence/admission-local.json) and [hosted evidence](evidence/admission-hosted.json) record exact outcomes and hashes. The hosted run also passed all existing quality gates and all 80 runtime network-policy probes.

## Operational limitations

- kindnet supplies connectivity while the digest-pinned policy agent supplies enforcement in the two-node test. Runtime TCP 8080 and UDP DNS 53 flows are now verified. Other CNIs, kernels, protocols, ports and IPv6 are not covered by this matrix. The older port-forward check remains a service-behavior check only.
- Runtime seccomp is set to RuntimeDefault and accepted by the cluster; exact allowed/denied syscall behavior is platform-dependent and is not individually probed.
- Reproducibility is two uncached builds in one configured environment, not an independent cross-host rebuild. The host engine, runner image, Python, C compiler and other host tools are not all digest-pinned. BuildKit itself now uses a digest-pinned disposable container builder.
- Inventory and scanning cover discovered packages in the final image, including the Go standard library. They do not audit builder-image packages, pipeline-tool vulnerabilities, every application logic bug, or unknown vulnerabilities. Zero findings is a dated scanner result only.
- LOW/MEDIUM findings are visible but do not block. A high-severity risk acceptance is not an exploitability determination; no VEX is emitted.
- The chart has one replica, fixed small resources and no ingress, TLS, authentication or availability guarantees. CPU or memory pressure can make probes fail. Its diagnostics are for a small functional demonstration.
- Signature verification is enforced at admission in enrolled namespaces after the explicit verifier installation. This policy checks image signatures; SBOM/evidence attestations remain CLI checks. Administrators can alter enrollment, policy or webhooks. Additional network policies can broaden effective access.
- Release publication can leave unsigned staged images if a later step fails. Only a completed release with successful signature and both attestation verifications is a supported deployment input.
- Anonymous pulls and verification were tested for this published release. Private forks and mirrors may require credentials; public source alone does not establish package visibility.
- Hosted artifact retention is finite; final release assets preserve the principal evidence. Scheduled scanning depends on the hosted scheduler, repository activity and service availability; it is not a continuous runtime monitor.
