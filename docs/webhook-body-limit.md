# Webhook request-body limit

The MEDIUM finding `GHSA-2hw4-c9m4-f2fj` came from an unbounded request-body read in the verifier's webhook library. The admission decoder also retained a copy for later policy validation. A sufficiently large request could exhaust memory. The conversion decoder used the same unbounded server boundary.

The dependency patch now selects `knative.dev/pkg v0.0.0-20260820190123-c9015f8bfdea`, a fixed revision compatible with the pinned telemetry SDK. It includes the [advisory's fix](https://github.com/knative/pkg/security/advisories/GHSA-2hw4-c9m4-f2fj): the [shared server mux](https://github.com/knative/pkg/commit/52dbd5ece63fe6d2d340ecbebec160550f460818) has a **3 MiB** read limit. It covers all four admission endpoints and the conversion endpoint, including bodies without a known Content-Length.

This uses the fixed upstream module instead of maintaining a local production backport. Its required dependency cohort includes Kubernetes client libraries at `v0.35.7` and newer telemetry packages. The complete module/checksum changes are recorded in the existing dependency patch; builds retain `-mod=readonly` and `go mod verify`. The controller's production freshness code and all scan/signature/attestation policies are unchanged. No exception or new VEX case is used for this finding.

The first unpublished candidate also exposed three LOW entries for `CVE-2026-81870` in the trace-exporter modules selected at their minimum `v1.43.0` versions. All three affected exporters are now pinned to `v1.46.0`, matching the existing telemetry SDK and exceeding the [advisory's first fixed version](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-8wmf-6v46-5gfg). [Candidate evidence](evidence/webhook-body-limit-candidate.json) preserves that intermediate scan instead of presenting it as a zero-finding result.

The first scan-clean candidate then failed real cluster startup: its default telemetry resource merged schema `1.40.0` with the SDK's `1.43.0` and panicked. It executed no admission cases. [Failure evidence](evidence/webhook-body-limit-schema-candidate.json) preserves the candidate identity and error. The selected [schema-alignment revision](https://github.com/knative/pkg/commit/c9015f8bfdea2ca0c38726e9f0a0506617840ced) uses schema `1.43.0`; two new startup regressions fail with the earlier candidate and pass with this revision, preserving service-name overrides and namespace/Pod attributes. No panic or schema-validation error is ignored in production.

## Bounded regression

The downstream source patch adds `pkg/webhook/body_limit_test.go`. It constructs the real exported server and calls its real admission and conversion handlers with small stub controllers. It does not copy the vulnerable decoder into a separate demonstration. All requests stay below 3.2 MiB, so the regression does not attempt to exhaust memory.

Both handler types exercise nine cases:

- Ordinary valid JSON and valid JSON exactly at the 3 MiB cap.
- One byte over the cap and a larger overflow.
- Unknown request length, an intentionally misstated length, and excess leading whitespace.
- An ordinary controller denial and an unsupported content type.

The ten oversized cases must return HTTP **400** containing `http: request body too large`, reach no controller callback, and read at most **3,145,729 bytes**, including one overflow byte. HTTP 400 preserves this library's decoder-error behavior; the fix does not introduce HTTP 413. Ordinary requests retain UID, API version, response kind, allow/deny status and the admission body's reread behavior. Unsupported content type still returns HTTP 415.

These are in-memory server tests with known, unknown and misstated request metadata. They do not claim a sustained-load, network-framing or memory-amplification measurement. The full cluster suite separately exercises legitimate signature and attestation decisions.

## Executed local results

Observed on 2026-10-30. [Structured evidence](evidence/webhook-body-limit-local.json) records the module versions, exact build identity and raw report hashes.

| Check | Exact result |
| --- | --- |
| Same regression against the previous module | Exit 1: 10 oversized cases fail because they reach the controller; 8 normal/boundary controls pass |
| Fixed module | Exit 0: all 18 body-limit cases pass |
| Existing freshness checks | All 29 leaf cases pass |
| Existing upstream key/HTML checks | All 25 leaf cases pass |
| `make test` | Exit 0, including vet and race checks |
| Workflow lint, trust-boundary guard and shell syntax | Exit 0 |
| Earlier scan-clean candidate | Build/scan exit 0 with only the bounded OpenPGP finding, followed by a failed cluster bootstrap due to schema mismatch |
| Observability startup regression | Earlier candidate: 2 cases fail; compatible fixed revision: both pass |
| Compatible revision's Linux amd64 build and scan | Exit 0: no LOW, MEDIUM, HIGH or CRITICAL entries; one existing bounded OpenPGP UNKNOWN finding remains |
| Compatible revision's native arm64 full admission replay | Exit 0 in 577.399s: 336 observations across all five suites, zero unexpected admissions |
| Local independent recompilation | Not run; mandatory in the verifier release workflow |

The compatible Linux amd64 cross-build is `sha256:0d8d2e57c375c5175c38a32345ed572c5f83c45885c1e9f4c2bba86fefc5b65d`. The separate native arm64 runtime build is `sha256:b3f83f4957ed77f0fdfb9ef3ed86f581dab49786c57a3786a12ac49418a7111e`. [Local runtime evidence](evidence/webhook-body-limit-runtime-local.json) records 30 signature/attestation requests, 42 availability requests, 65 maintenance requests, 16 multi-control-plane requests and 183 trust-update probes. Transient unavailability is counted separately from policy denials. The network suite was not rerun locally for this fix.

The superseded scan-clean candidate's cross-build was `sha256:6fd6c154e14206be51bc5703b2f0af9a7c6869719e529232015a896860ab8afc`. It is not a supported release. [The first hosted run](evidence/webhook-body-limit-first-hosted.json) also failed installation before the admission suite started. These failed candidates remain in the evidence history.

```sh
make tools
make test
CONTROLLER_ARCH=amd64 make controller-image
./scripts/scan-controller.sh
make admission
make cluster
```

The verifier build runs the new cases alongside the existing freshness checks and retains their output in `unit-tests.txt`. A release's evidence attestation authenticates that report hash. Hosted and published-image results are separate from the local results above.

## Hosted results

The [protected pull-request run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/41106134124) passed on 2026-10-30. It tested checkout `d8a45f57195459c331e065d4b3f0b0a3af87c7c6`, whose source tree matches merged commit `4c20b82215c9331afbad30da32819e7ad5a60307`. [Structured hosted evidence](evidence/webhook-body-limit-hosted.json) includes report hashes, exact outcomes and the Linux amd64 digest matching the local cross-build.

| Hosted suite | Observations | Result |
| --- | --- | --- |
| Signature and attestations | 30 | Passed |
| Availability and recovery | 40 | Passed |
| Maintenance gate | 65 | Passed |
| Three-control-plane decisions | 16 | Passed |
| Trust updates | 183 | Passed |
| Admission total | 334 in 529.281s | Zero unexpected admissions |
| Runtime network policy | 80 | Zero mismatches |
| Verifier unit tests | 74 leaf cases | Passed |
| Fresh verifier scan | 1 existing OpenPGP UNKNOWN | Zero LOW, MEDIUM, HIGH or CRITICAL entries |

The full admission run was selected, with no suite filter. All application, workflow, policy, build, signing and runtime gates also passed. Request totals include transient fail-closed errors during recovery; those errors cannot count as a successful policy denial.

## Releases and limits

The fixed release is `controller-v0.1.3`, from merged source `4c20b82215c9331afbad30da32819e7ad5a60307`. Require its [completed release workflow](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/41109457087) and published assets before installation. That workflow independently recompiles the verifier, scans it again, signs the exact digest, adds SBOM and evidence attestations, checks both negative verification cases, and reruns the complete admission suite against the published image. Its release assets and workflow report provide the publication-specific outcomes. Earlier `controller-v0.1.2` evidence remains a historical result and its image still contains the old module. Historical verification requires the matching release-tag source because signed patch and module identities must agree.

The cap limits bytes consumed by these handlers, not total process memory or concurrent requests. Valid reviews larger than 3 MiB are rejected. A completed JSON value can leave trailing bytes unread; this does not restore unbounded decoder allocation. The tests do not establish production capacity or independent-host availability. Administrator, build-host and node trust boundaries remain as documented in the threat model.
