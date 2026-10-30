# Webhook request-body limit

The MEDIUM finding `GHSA-2hw4-c9m4-f2fj` came from an unbounded request-body read in the verifier's webhook library. The admission decoder also retained a copy for later policy validation. A sufficiently large request could exhaust memory. The conversion decoder used the same unbounded server boundary.

The dependency patch now selects `knative.dev/pkg v0.0.0-20260531000007-52dbd5ece63f`, the first fixed version named by the [advisory](https://github.com/knative/pkg/security/advisories/GHSA-2hw4-c9m4-f2fj). The [official fix](https://github.com/knative/pkg/commit/52dbd5ece63fe6d2d340ecbebec160550f460818) wraps the shared server mux with a **3 MiB** read limit. It covers all four admission endpoints and the conversion endpoint, including bodies without a known Content-Length.

This uses the fixed upstream module instead of maintaining a local production backport. Its required dependency cohort includes Kubernetes client libraries at `v0.35.4` and newer telemetry packages. The complete module/checksum changes are recorded in the existing dependency patch; builds retain `-mod=readonly` and `go mod verify`. The controller's production freshness code and all scan/signature/attestation policies are unchanged. No exception or new VEX case is used for this finding.

The first unpublished candidate also exposed three LOW entries for `CVE-2026-81870` in the trace-exporter modules selected at their minimum `v1.43.0` versions. All three affected exporters are now pinned to `v1.46.0`, matching the existing telemetry SDK and exceeding the [advisory's first fixed version](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-8wmf-6v46-5gfg). [Candidate evidence](evidence/webhook-body-limit-candidate.json) preserves that intermediate scan instead of presenting it as a zero-finding result.

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
| Actual Linux amd64 verifier build and fresh scan | Exit 0; the MEDIUM finding is absent; 0 LOW, MEDIUM, HIGH or CRITICAL findings |
| Existing bounded VEX | Only `GO-2026-5932` remains in the raw scan; its affected OpenPGP packages are absent from the compiled closure |
| Local independent recompilation | Not run; mandatory in the verifier release workflow |

The local cross-build produced manifest `sha256:6fd6c154e14206be51bc5703b2f0af9a7c6869719e529232015a896860ab8afc`.

```sh
make tools
make test
CONTROLLER_ARCH=amd64 make controller-image
./scripts/scan-controller.sh
make admission
make cluster
```

The verifier build runs the new cases alongside the existing freshness checks and retains their output in `unit-tests.txt`. A release's evidence attestation authenticates that report hash. Hosted and published-image results are separate from the local results above and will be recorded in the fix's pull request and release assets after execution.

## Releases and limits

The fixed release target is `controller-v0.1.3`. Require its completed release workflow and published assets before installation. Earlier `controller-v0.1.2` evidence remains a historical result and its image still contains the old module. Historical verification requires the matching release-tag source because signed patch and module identities must agree.

The cap limits bytes consumed by these handlers, not total process memory or concurrent requests. Valid reviews larger than 3 MiB are rejected. A completed JSON value can leave trailing bytes unread; this does not restore unbounded decoder allocation. The tests do not establish production capacity or independent-host availability. Administrator, build-host and node trust boundaries remain as documented in the threat model.
