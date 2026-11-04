# November 3 advisory review and scan reliability

The [November 3 scheduled run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/41655259692) stopped with `advisory changed; review before release`. Application tests, builds, policy checks and local signing had passed. The verifier built and ran its 74 focused cases, but its advisory guard stopped the scan stage before the full admission suite started. The network stage was skipped. These stages are not counted as passing runtime checks.

The guard was doing its job. [GO-2026-5932](https://vuln.go.dev/ID/GO-2026-5932.json) changed on November 2: it now identifies a fixed parent-module revision and a separate legacy OpenPGP module. The legacy module remains unsafe. The old evaluator also rejected the new advisory after changing only its checksum, because its reviewed scope no longer matched. The failure and the earlier passing runs remain in the history.

## Change

The dependency patch upgrades only `golang.org/x/crypto`, from `v0.58.0` to the advisory's first fixed revision, `v0.58.1-0.20261009181718-2f1f834330b2`, and updates its authenticated checksums. The [upstream change](https://github.com/golang/crypto/commit/2f1f834330b2d36ab3db8bfb33aaa1ac16794588) separates the legacy OpenPGP module. The verifier does not import it. The remaining dependency graph, compiler and runtime policy patches are unchanged; module verification and readonly builds remain mandatory.

The reviewed advisory JSON is now a checked-in, checksum-locked build input. A mutable advisory page no longer changes a reproducible build merely because its metadata was edited. Scanning still downloads a fresh vulnerability database, checks its age, and evaluates every raw finding. A future HIGH, CRITICAL or UNKNOWN finding must stop the gate. LOW and MEDIUM findings remain visible under the existing policy.

The old scan filter is removed. The policy reads `scan.json` directly. The compatibility file `scan-policy-input.json` must contain the same bytes. VEX records `fixed` for the exact image and pinned parent module, with no finding exclusion or severity change. The record requires both reviewed advisory scopes/ranges, the exact fixed module inventory and absence of the legacy module and its package family. If the advisory reappears in the raw scan, generation stops for review. This does not claim that the unmaintained legacy code was repaired.

## Executed local results

Observed on 2026-11-03. [Structured evidence](evidence/advisory-review-local.json) includes source/build identities, failed controls and report hashes.

| Check | Result |
| --- | --- |
| Old lock with the changed advisory | Rejected with the same checksum-review error |
| Old evaluator with only its advisory hash refreshed | Rejected because the advisory scope changed |
| Dependency update | Only one module version and its two checksums changed; `go mod verify` passed |
| Root tests | `make test` passed, including vet and race checks |
| Remediation tests | 3 methods passed: 32 unsafe variants rejected, 4 positive controls passed, exact raw-byte copy verified |
| Workflow and syntax checks | Workflow lint/trust guard, Python compilation, shell syntax and whitespace checks passed |
| Verifier regression tests | All 74 leaf cases passed, including all body-limit and startup cases |
| Linux amd64 cross-build | `sha256:994c969861768d50cf421adbf5e3f15035282aa23a1ba8432a6e760da11fac19` |
| Fresh raw scan | Zero findings; no filtering applied |
| Raw and compatibility scan input | Byte-identical |
| Local independent recompilation | Not run; mandatory in the release workflow |
| Local full cluster replay | Not run for this fix; hosted full-suite results are recorded separately |

```sh
make tools
make test
CONTROLLER_ARCH=amd64 make controller-image
./scripts/scan-controller.sh
make admission
make cluster
```

`controller-v0.1.4` is the release target. Adoption requires its completed quality, publication and published-image replay gates, plus authenticated downloaded reports. Hosted results and source revisions are recorded in the fix's pull request and release after execution. Earlier release evidence requires the matching tag's source because the signed dependency patch and VEX profile must agree.

## Hosted results

The [protected fix run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/41739135181) passed all quality gates on 2026-11-03. It tested checkout `1a98f1c96d6e4d8edbd89a796aee9e28c3ad8d17`. The PR head and merged source `77c03fab4e0d47fcb7cff2a9effe91ccf8ed3fa8` share the same source tree `a28749549a5625c54823942470406eac809dc7b8`. [Structured hosted evidence](evidence/advisory-review-hosted.json) records the image identity, all outcomes and raw report hashes.

| Suite | Observations | Result |
| --- | --- | --- |
| Signature and attestations | 31 | Passed |
| Availability and recovery | 43 | Passed |
| Maintenance gate | 65 | Passed |
| Three-control-plane decisions | 16 | Passed |
| Trust updates | 183 | Passed |
| Admission total | 338 in 517.009s | Zero unexpected admissions |
| Runtime network policy | 80 | Zero mismatches |
| Verifier unit cases | 74 | Passed |
| Fresh raw scan | Zero findings | No filtering applied |

The full admission run was selected, with no suite filter. Transient fail-closed errors are retained separately from successful policy denials. The hosted Linux amd64 manifest matches the local cross-build. The [controller-v0.1.4 release workflow](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/41742227700) separately requires independent recompilation, signing, both attestations, negative verification cases and a full replay against the published digest. Its release assets record those publication-specific results after execution.

## Limits

The daily quality workflow remains enabled, with pinned actions, restricted job permissions and mandatory negative security checks. There are no success overrides or retries that accept a security denial. New vulnerabilities, invalid evidence and unavailable required services can still stop the pipeline. Passing results are dated observations, not a guarantee that future scans will remain clear. The existing single-host, administrator/build-host trust and unmeasured-capacity limits still apply.
