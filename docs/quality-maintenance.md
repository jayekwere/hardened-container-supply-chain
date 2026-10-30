# Scheduled quality-check maintenance

Reviewed on 2026-10-30. The three scheduled failures ran the same source revision, `89200c5b590c638298b79a856fba5368e425f093`, that passed on October 27. They had two separate causes.

| Run | Failure | Change |
| --- | --- | --- |
| [October 28](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40696578858) | Kubernetes stopped a verifier task between inventory and SIGKILL. The test treated another live replica as evidence that the already-exited task failed to stop. | Recheck the specific task ID after a signal error. Continue requiring zero running verifier processes and zero ready endpoints before the outage request. |
| [October 29](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40883589134) | The verifier scan rejected one HIGH and two UNKNOWN findings. | Upgrade the two affected modules and their authenticated checksums. |
| [October 30](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/41063149761) | The same three blocking dependency findings recurred. All preceding application, network and admission steps passed. | Scan each local verifier build before creating its admission cluster, so this failure appears earlier. |

## Dependency remediation

| Finding | Previous module | Fixed module |
| --- | --- | --- |
| CVE-2026-116587, RSA JWK validation CPU exhaustion | `github.com/go-jose/go-jose/v4 v4.1.5` | `v4.1.6` |
| CVE-2026-78661, HTML text coalescing allocations | `golang.org/x/net v0.61.0` | `v0.62.0` |
| CVE-2026-97045, HTML foreign-content rendering | `golang.org/x/net v0.61.0` | `v0.62.0` |

Primary references: [JWK advisory](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q), [HTML parsing advisory](https://vuln.go.dev/ID/GO-2026-6860.json), [HTML rendering advisory](https://pkg.go.dev/vuln/GO-2026-6866).

The failed binary's import closure contains go-jose but excludes `golang.org/x/net/html`. Module presence does not prove that an attacker can reach an affected function through admission. Both modules are upgraded anyway. No new VEX or exception is used, and no severity is lowered. The existing OpenPGP-only VEX keeps its original scope and retains the original finding in the raw report.

The patch changes only these two resolved module versions and their `go.sum` records. Source preparation still checks the archive, both patches and the prepared tree. Builds keep `-mod=readonly` and `go mod verify`. The upgraded JWK parser limits RSA moduli to 4096 bits by default; unusually large legitimate JWKs can now be rejected. This project does not override that bound.

## Regression checks

`TestVerifierTaskStop` has six cases: no tasks, successful signal, a task that exits before its signal, an exited task while another replica remains, a replacement task, and a signal failure while the target remains live. The old global-inventory condition fails the two replica/replacement cases; the target-specific condition passes all six. The caller still waits for the full outage and performs a real fail-closed admission request.

The verifier build also runs upstream `TestRsaKeyChecks`, `TestEmbeddedPrivateJWKRejected`, `TestPrivateEPKRejected`, `TestUnmarshalPrivateJWKAllowed`, and `TestRoundtripRsaPrivate`, plus HTML `TestTextNodeCoalescing`, `TestRenderFosteredForeignContent` and `TestRenderer`. This exercises malicious key/header representations, both HTML fixes and ordinary key/HTML behavior. Output joins the existing `unit-tests.txt` evidence so release attestations authenticate its hash. This is a focused selection, not the full upstream suite.

```sh
make tools
make test
.tools/bin/actionlint
python3 scripts/check-workflows.py
CONTROLLER_REPRODUCE=1 make controller-image
./scripts/scan-controller.sh
make check
./scripts/sign-local.sh
make admission
make cluster
```

`make admission` now scans a locally built verifier before creating its cluster. When testing a published verifier, it verifies that exact release's signature and attestations instead; publication already requires a fresh scan. The quality workflow retains read-only permissions, SHA-pinned actions and failure evidence. Its summary shows each stage's actual outcome, including skipped stages.

## Verification status

The task-stop reproduction failed with the previous condition and passes with the fix. `make test`, actionlint, workflow trust-boundary checks and shell syntax checks passed locally. The native Linux arm64 verifier build, upstream security regressions, independent recompilation and fresh image scan all exited 0. The three blocking findings are absent from the rebuilt image; the raw OpenPGP UNKNOWN remains and only its existing bounded VEX case is applied. [Structured local results](evidence/quality-maintenance-local.json) bind these observations to their build inputs and raw report hashes.

That raw scan also contains one MEDIUM, `GHSA-2hw4-c9m4-f2fj` in `knative.dev/pkg`. The existing policy exposes LOW/MEDIUM findings and blocks HIGH, CRITICAL and UNKNOWN; it does not require a risk exception for MEDIUM. This advisory is neither suppressed nor described as remediated. The passing gate is not a zero-finding claim.

| Local verification | Exact result |
| --- | --- |
| Task-stop regression | 6 cases pass; the previous condition fails the 2 replica/replacement races |
| Verifier freshness regressions | 29 leaf cases pass |
| Upstream dependency regressions and legitimate controls | 25 leaf cases pass across 8 selected top-level tests |
| Native Linux arm64 build and fresh scan | Exit 0; independent recompilation is byte-identical |
| Linux amd64 cross-build and fresh scan | Exit 0; manifest `sha256:2006b0d693326fc0abdacc9836f58da122bf15f03c92de3aa10c676d0cf884f5`; independent amd64 recompilation is reserved for the release gate |
| Raw scan | 0 HIGH, 0 CRITICAL, 1 MEDIUM and 1 UNKNOWN; the existing bounded OpenPGP VEX handles only the UNKNOWN |
| Old scan replay through the unchanged gate | Exit 1, with all 3 original blocking reasons |

## Hosted fix results

[Quality run 41084094730](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/41084094730) passed every stage. The full admission package completed in **500.950 seconds** and the network package in **40.838 seconds**. The tested head was `ffd1d88e47c5dba24a3ea7ccd363f0090628d5c2`; its checkout tree and merged commit `8689c76f2fc83470ce634b50071e3f341e33cdf8` have the same tree hash, `5b5a69f27e94e665019290fad09a59f738222c73`. The hosted verifier manifest matches the local Linux amd64 cross-build.

| Suite | Recorded observations | Exact outcomes |
| --- | --- | --- |
| Signature and attestations | 31 requests, 30 cases | 11 allowed, 5 signature denials, 1 no-policy denial, 4 identity denials, 8 attestation denials, 2 unavailable |
| Verifier-node, elected-leader and quorum faults | 46 requests, 34 logical controls | 16 allowed, 16 signature denials, 12 unavailable, 2 storage unavailable |
| Maintenance | 65 | 23 allowed, 39 maintenance denials, 3 signature denials |
| Direct multi-control-plane | 18 requests, 16 controls | 8 allowed, 8 signature denials, 2 unavailable |
| Trust updates | 183 | 31 allowed, 26 signature denials, 51 identity denials, 50 freshness denials, 25 extra-policy denials |
| Runtime NetworkPolicy | 80 | All expectations matched |

Total admission observations: **343, with zero unexpected admissions**. Transient unavailability remains visible and cannot count as a cryptographic policy rejection. The run-selection record confirms the full suite. [Structured hosted evidence](evidence/quality-maintenance-hosted.json) contains source identity, exact counts and raw report hashes. The same six task-stop cases, 29 verifier freshness cases and 25 upstream dependency cases passed on the hosted runner.

The replacement tag is `controller-v0.1.2`, targeting the normally merged source commit `8689c76f2fc83470ce634b50071e3f341e33cdf8`. Publication is conditional on the existing quality and release gates; selecting its reference in source does not establish that publication completed. Check the [release workflow](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/41088764691) and published assets before installation. Publication and post-publication runtime results are separate from this PR-quality result and are retained in [the fix's pull request](https://github.com/jayekwere/hardened-container-supply-chain/pull/10), job artifacts and release assets. Earlier release and scan results remain historical.

Daily checks use a current vulnerability database. A future finding can correctly make a previously passing source revision fail again. Updating a dependency requires a new build, scan, signatures and evidence; a green result does not permanently certify an older image.
