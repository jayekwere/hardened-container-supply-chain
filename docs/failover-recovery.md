# Failover replay and recovery checks

The October 27 [scheduled run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40505124491) failed after the survivors elected a new storage leader: a valid request still timed out calling the verifier. It failed closed. That run's final diagnostics were taken after later tests changed the Deployment, so they do not prove one exclusive cause for the timeout.

The replay had two uncontrolled conditions. Both default DNS replicas could occupy the first control-plane node, and the next fault could begin after API readiness without checking verifier or DNS recovery. The disposable cluster now requires DNS replicas on separate hostnames. Between faults it requires all expected nodes ready, two ready verifier Pods on distinct nodes, two ready DNS Pods on distinct nodes, and service endpoints matching the current verifier Pod UIDs, IPs and nodes. Missing, stale, terminating, unready or mismatched endpoints cannot satisfy the barrier. The barrier has a 120-second limit; admission recovery retains its existing 90-second limit.

A separate local before-change replay also exposed an unrecognised client timeout during intentional quorum loss. The storage write failed and the signed-image request was rejected, but `Client.Timeout exceeded while awaiting headers` was not classified as an availability failure. That exact form is now covered, with a regression proving that an authorization error containing the same words is still rejected as evidence. A timeout never counts as a signature or attestation denial.

Failure diagnostics are now captured before test cleanup resumes paused nodes or another suite rolls the verifier. The verifier binary, published signature/SBOM/evidence and production installer values are unchanged; this update corrects failure isolation, recovery checks and evidence classification.

## Reproduce

```sh
make tools
make test
make admission
```

A focused replay needs the signature suite's namespace setup:

```sh
TEST_ADMISSION_RUN='^(TestAdmissionSignatures|TestAvailability)$' make admission
```

That focused command is not a full-suite result. The recorded passing run below selected `.` and executed the entire admission package.

## Local result, October 27, 2026

[Machine-readable results](evidence/failover-recovery-local.json) bind the changed source files, native Linux arm64 verifier build, raw evidence and test output by SHA-256.

| Check | Exact result |
| --- | --- |
| `make test` | Passed, including vet, race tests, locked inputs, policy tests, 11 recovery-readiness cases and 11 quorum-error classification cases |
| Full `make admission` Go invocation | Passed in 367.545 seconds |
| Signature and attestation matrix | 30 cases in 30 requests; 11 intended admissions, 18 policy denials and 1 expected unavailable response |
| Availability | 34 logical controls in 40 observations; 16 intended admissions, 16 signature denials, 6 transient webhook failures and 2 required quorum-loss availability failures; 149.69 seconds |
| Elected leader paused | Both survivors reported a different leader; each admitted the signed image and rejected the unsigned image, with no retry in this phase |
| Maintenance | 65 observations: 23 intended admissions, 39 maintenance denials and 3 signature denials |
| Three explicit API endpoints | 16 observations: 8 intended admissions and 8 signature denials |
| Trust updates | 183 probes: 31 intended admissions and 152 required denials; zero unexpected admissions |
| Workflow and patch checks | actionlint and `git diff --check` passed |

Across the five runtime suites there were 334 recorded observations and zero unexpected admissions. Transient failures remain recorded; they are not relabelled as successful policy enforcement. Historical failed runs and published release evidence are retained separately. This local run did not repeat `make check` or the NetworkPolicy suite; the required hosted quality workflow runs those alongside the full admission suite.

## Remaining limits

These are containerized nodes on one host. The result does not establish physical-host resilience, arbitrary partition handling, sustained-load availability or zero downtime. Recovery readiness is an observed condition, not a promise that a later failure cannot occur. Quorum loss remains unavailable by design. Real installations need resilient DNS, verifier placement and routing appropriate to their environment; the DNS placement adjustment here is scoped to the disposable cluster. The existing trust-update races, administrator boundary and lack of retroactive Pod enforcement remain documented in the operating guide.
