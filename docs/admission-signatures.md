# Admission-time image signature enforcement

The API server now has a reproducible signature-verifying admission installation and Go integration suite. The trust rule accepts this repository's exact release workflow identity and OIDC issuer, with normal certificate and transparency-log verification. The controller image and installation chart are pinned; no signing secret or private certificate is committed.

The current installation also requires signed SBOM and evidence attestations through a separate mandatory policy. See [attestation requirements and the expanded suite](admission-attestations.md). The 16-case execution records below describe the original signature-only implementation; the current `make admission` runs the expanded suite.

## Reproduce the complete test

```sh
make tools
make test
make admission
```

`make admission` creates a fresh, explicitly named kind cluster, verifies the chart checksum, installs the controller with TLS and `failurePolicy: Fail`, applies the release trust policy, and runs the live API-server decisions. It removes the cluster and its private kubeconfig on success or failure. It never selects an existing cluster. The normal quality workflow runs this command alongside the earlier container and network-policy checks.

Raw decisions and errors are written to `artifacts/admission/decisions.json`; test output, node/controller metadata and independently resolved fixture digests are retained alongside it. Hosted runs upload these files with normal quality-evidence retention.

## Install into an explicitly selected cluster

The reusable installer requires an explicit kubeconfig. It creates `image-policy-system` and installs the pinned controller, `release-signer` policy and `release-attestations` policy. The selected cluster must permit the controller's installation RBAC and have public registry/trust-service connectivity. Use a fresh namespace for the replay examples:

```sh
./scripts/install-admission.sh /absolute/path/to/kubeconfig
kubectl --kubeconfig /absolute/path/to/kubeconfig apply -f examples/admission/namespace.json
kubectl --kubeconfig /absolute/path/to/kubeconfig wait -n signature-demo \
  --for=create serviceaccount/default --timeout=20s

# Expected: exit 0; admitted by the real API-server webhooks.
kubectl --kubeconfig /absolute/path/to/kubeconfig create --dry-run=server \
  -f examples/admission/pass-pod.json -o json

# Expected: exit 1; the signature verifier explicitly denies the unsigned image.
kubectl --kubeconfig /absolute/path/to/kubeconfig create --dry-run=server \
  -f examples/admission/fail-pod.json -o json
```

These fixtures contain a scheduling gate. The test persists one signed Pod and verifies it exists; that Pod stays unscheduled. The remaining requests use server-side dry run, including real signed/unsigned Helm Deployment templates and ephemeral-container subresource updates. These are admission decisions, not claims that the admission fixture image executed. Runtime execution is covered separately by the existing container and network suites.

For a real deployment, enroll its namespace with `policy.sigstore.dev/include=true`, then deploy the digest-pinned chart normally. The installer does not silently enroll existing namespaces. For example, enrolling `supply-demo` makes the published signed release subject to the verifier when its Deployment and Pods are admitted.

## Trust and default-deny behavior

The [ClusterImagePolicy](../integration/admission/release-policy.json) has one keyless authority:

- Image repository: `ghcr.io/jayekwere/hardened-container-supply-chain`.
- Certificate subject: `https://github.com/jayekwere/hardened-container-supply-chain/.github/workflows/release.yml@refs/tags/v0.1.1`.
- OIDC issuer: `https://token.actions.githubusercontent.com`.
- Transparency log: `https://rekor.sigstore.dev`.

There are no wildcard signer identities, static-pass authorities, insecure SCT skips, or log-verification bypasses. A future release tag requires an explicit reviewed policy update. The application chart continues to require a digest. The controller's normal image resolver runs before signature validation; the recorded cases all supply digest references.

`no-match-policy: deny` rejects images that match no trust policy in enrolled namespaces. The mutating and validating webhooks both use `failurePolicy: Fail`. The tests inspect the effective API-server configurations for nonempty rules, a TLS CA bundle, and fail-closed behavior, and check the deployed controller image against the lock.

The signed fixture is the actual public release. The unsigned fixture is the existing repacked manifest from the unsupported earlier upload. Both manifest digests are independently resolved before testing; an absent image is not accepted as evidence of missing signatures. Although their root filesystem content is related, a signature for the signed manifest cannot authenticate a different manifest digest.

## Passing and intentionally failing cases

| Case | Required decision |
| --- | --- |
| Signed Pod, actually persisted with scheduling gate | Admit |
| Signed Deployment rendered from the application chart | Admit |
| Unsigned Pod | Deny: missing signature |
| Signed Pod with an unsigned sidecar | Deny: missing signature |
| Signed Pod with an unsigned init container | Deny: missing signature |
| Unsigned Deployment rendered from the chart | Deny: missing signature |
| Image from a repository with no matching policy | Deny: no policy |
| Signed ephemeral-container update | Admit |
| Unsigned ephemeral-container update | Deny: missing signature |
| Signed image while trust expects a different workflow | Deny: identity mismatch |
| Signed image while trust expects a different issuer | Deny: identity mismatch |
| Correct trust policy restored | Admit |
| Unsigned Pod outside the enrolled namespace | Admit: explicit scope control |
| Trusted image while the verifier is stopped | Reject: webhook unavailable, fail closed |
| Unsigned Pod outside scope during that outage | Admit: API-server liveness/scope control |
| Verifier restored | Admit |

The outage test scales the verifier to zero and force-deletes its Pods **only in the newly created disposable cluster**. It confirms the runtime can see a running verifier, terminates only verifier runtime tasks in that namespace to end their long drain period and existing connections, waits for both the runtime processes and Service endpoints to disappear, then checks rejection without changing `failurePolicy`. This includes an older draining instance after the attestation fixture CA reload. It restores the verifier and requires successful admission afterward. Simply removing Service endpoints did not interrupt an already-established webhook connection, so that weaker fault injection is not used as outage evidence.

Changing signer trust after a successful verification also exercises policy-cache invalidation: the already-signed image must be rejected under the wrong subject/issuer and admitted again after restoration.

The harness records every attempt during bounded policy propagation or verifier recovery. Only explicit denials from `policy.sigstore.dev` with the expected reason count as signature/policy failures. Schema failures, Pod Security errors, unrelated webhooks, registry timeouts and client failures do not count as passing signature tests. Separate unit regressions cover those classifications.

## Original signature-only results

The final local run on 2026-10-25 (America/Vancouver) passed **16 cases in 16 API requests**, with **zero transition attempts**: 7 admissions, 5 missing-signature denials, 2 identity denials, 1 no-policy denial, and 1 fail-closed webhook-unavailable rejection. The verifier-unavailable request returned exit 1 after its configured 20-second webhook timeout; after restoration the trusted image returned exit 0. All 13 classification regressions passed. The disposable cluster was removed.

[Local structured evidence](evidence/admission-local.json) records exact per-case outcomes, timestamps, versions and source/raw-evidence hashes. The [hosted quality run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40252400191) independently passed the same **16 cases and 13 classification regressions** on Linux amd64. It issued **17 requests**, including **1 recovery transition**: the first request after restoring the verifier returned connection refused (exit 1), and the second was admitted (exit 0). All final decisions matched the matrix. The [hosted evidence](evidence/admission-hosted.json) preserves that transition, the final decisions, artifact identity/digest, versions, timestamps and source/raw-evidence hashes. The full quality run, including the 80-probe network-policy suite, passed.

Selected actual test output from that hosted run:

```text
signed-pod-persisted: allowed (exit 0, attempt 1)
unsigned-pod: signature-denied (exit 1, attempt 1)
wrong-workflow: identity-denied (exit 1, attempt 1)
verifier-unavailable-fail-closed: unavailable (exit 1, attempt 1)
verifier-restored: allowed (exit 0, attempt 2)
--- PASS: TestAdmissionSignatures (49.12s)
```

The unsigned-image denial included `admission webhook "policy.sigstore.dev" denied the request` and `no signatures found`. The outage rejection included `failed calling webhook "policy.sigstore.dev"` and `context deadline exceeded`. These are separate expected failure classes; neither is inferred from a generic nonzero exit code.

## Scope and operational limits

- Enforcement applies to namespaces labeled `policy.sigstore.dev/include=true`. The out-of-scope controls intentionally demonstrate that boundary. Administrators can change labels, trust policies, webhook configuration or the verifier; production RBAC must protect those controls.
- The signature policy verifies image signatures; the separately installed attestation policy now requires both signed SBOM and evidence predicates. A valid signature establishes expected signer identity and artifact integrity, not absence of vulnerabilities. See the [attestation content checks and limits](admission-attestations.md).
- Admission checks new/updated resources; it does not retroactively evict existing Pods when trust changes. The recorded resource coverage is Pod creation, the actual Helm Deployment template, init containers, sidecars and ephemeral-container updates.
- The demo uses one verifier replica. Fail-closed behavior intentionally blocks enrolled admissions when it is unavailable. A production operator should configure appropriate availability and test recovery there.
- Public registry and trust-root availability are operational dependencies. Cached verifications may avoid some remote lookups; the tests do not claim to simulate every external-service failure.
- Namespace enrollment is an administrator-controlled prerequisite. The standalone application Helm chart does not install the cluster-wide verifier or grant itself that authority.
- The checksum-locked chart and pinned controller image are a tested combination. The lock records their versions separately because the chart's app-version metadata predates the explicit image override.
- The chart's post-delete cleanup helper is pinned but is not executed by the disposable test. That runner deletes the whole cluster. If removing the installation manually, use `helm uninstall policy-controller -n image-policy-system --no-hooks` with the explicit kubeconfig, and review remaining cluster-scoped policy resources separately.

References: [controller installation](https://docs.sigstore.dev/policy-controller/installation/), [policy semantics](https://docs.sigstore.dev/policy-controller/overview/). Executed results are recorded independently above; tool documentation is not treated as proof of execution.
