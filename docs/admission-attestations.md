# Admission requirements for signed SBOM and evidence

Enrolled namespaces require **all three** controls: the image signature, a signed CycloneDX SBOM, and signed release evidence. The [signature policy](../integration/admission/release-policy.json) remains independent of the [attestation policy](../integration/admission/attestations-policy.json). Matching ClusterImagePolicies are combined with AND; the attestation authority requires both named predicate types. Adding attestations to the signature authority alone would replace its signature-verification path, so that approach is not used.

Both production policies use the exact v0.1.1 release workflow subject, expected OIDC issuer and normal certificate/transparency verification. There is no wildcard identity, test key, alternate source registry or static-pass authority in the installed production policies. The controller/chart pins, namespace enrollment and fail-closed webhooks are unchanged. The existing signed release is the public positive control; it is not rebuilt or republished by these tests.

## Reproduce

```sh
make tools
make test
make admission
```

The admission command requires OpenSSL in addition to the engine and prerequisites in the README. It creates a private kubeconfig and fresh kind cluster, installs both policies, and tests actual API-server decisions. It also starts a digest-pinned TLS fixture registry connected only to the disposable engine network, with a loopback-only host port. Its temporary certificate is trusted only by the test controller. All image requests still reference the real signed public image; only fixture attestation discovery is redirected to that local registry.

Each fixture envelope is signed with a freshly generated test key. The fixture sets contain both valid predicates, only one predicate, signed invalid content, an untrusted signature, a modified signed payload, or a signed statement for a different image digest. The tampered payload keeps the same valid claims and changes only the signed bytes, so content checks alone would accept it. They are synthetic test evidence, not release claims or real scan results. The original image-signature policy stays active throughout. The test swaps only the attestation policy's authority/source while preserving its exact production content checks, restores the complete fixture set, then restores the production keyless authority/source and requires admission again. Policy changes also exercise cache invalidation after a successful verification.

Private signing keys are deleted before the Go suite runs. Cleanup removes the registry, its temporary TLS key/certificate, the entire cluster and its kubeconfig on success or failure. No fixture or test signature is pushed to a public registry. Raw API decisions, public fixture inventory/envelope hashes, test output, deployed controller metadata and node details are retained in `artifacts/admission/` and the workflow evidence artifact.

Loading the fixture registry CA rolls the controller. The outage fault therefore stops every remaining verifier runtime task in the disposable namespace, including an older draining instance, and requires both zero running verifier tasks and zero ready Service endpoints before checking fail-closed rejection. Restoring the verifier must restore successful production admission.

## What the content policies check

| Predicate | Required content |
| --- | --- |
| `https://cyclonedx.org/bom` | CycloneDX format, spec version 1.7, positive integer document version, exactly one `stdlib` library component with version `v1.27.3` and its matching package URL |
| Repository evidence type ending in `/evidence/v1` | Schema version 1; exact reviewed source revision `fbd97e985473537e99f47e8e987b6ade222e3bc6`; image claim equal to the admitted statement subject digest; `release.yml` builder; Linux amd64; timestamp shape; all four required SHA-256 report references; exception ledger version 1 with no entries |

The verifier authenticates and checks the in-toto statement's image subject before evaluating its predicate. The evidence rule additionally compares its internal `image` claim with that subject, preventing an authenticated envelope from carrying contradictory image metadata. The profile intentionally describes the existing release. A different release, compiler, platform or exception decision requires a reviewed update to the profile and its tests. The exact source revision is not inferred from a mutable tag.

These are deliberately narrow content checks, not full CycloneDX schema validation, a fresh vulnerability scan, or proof that every listed package/report is complete or truthful. Report hashes are required in the authenticated evidence; admission does not fetch those reports or recompute their hashes against the SBOM predicate. Maintainers must still review the release assets and vulnerability evidence. There is no VEX or external provenance certification claim.

## New passing and intentionally failing cases

All earlier signature/container-field, namespace-scope, outage and recovery cases remain in the suite. These additional cases isolate the attestation requirements:

| Case | Expected API decision |
| --- | --- |
| Real release under a different attestation workflow identity | Deny identity |
| Real release under a different attestation issuer | Deny identity |
| Production attestation trust restored | Admit |
| Signed complete local fixture set | Admit |
| Evidence present, SBOM absent | Deny attestation |
| SBOM present, evidence absent | Deny attestation |
| Signed SBOM without the required standard-library component | Deny attestation |
| Signed evidence with a contradictory image claim | Deny attestation |
| Signed evidence with an unapproved source revision | Deny attestation |
| SBOM signed by an untrusted key, trusted evidence present | Deny attestation |
| Evidence payload changed after signing, trusted SBOM present | Deny attestation |
| Evidence validly signed for a different subject digest | Deny attestation |
| Complete fixture requirements restored | Admit |
| Real release and production attestation policy restored | Admit |

An authenticated envelope of the wrong type cannot satisfy another requirement. Invalid signatures or subjects can leave no verified envelope of the required type; those rejections are recorded as attestation denials, without claiming the controller always exposes the exact cryptographic failure in its API error. The harness requires the named `release-attestations` policy and a recognized denial reason. Regression cases reject registry timeouts, unrelated webhooks, broken policy compilation and schema/Pod Security failures as evidence of an expected attestation denial. Every propagation/recovery request is recorded, including any temporary disagreement before the expected decision.

## Install or update an explicit cluster

For a fresh controller installation:

```sh
./scripts/install-admission.sh /absolute/path/to/kubeconfig
```

For the previously installed pinned controller, apply both policies explicitly:

```sh
kubectl --kubeconfig /absolute/path/to/kubeconfig apply \
  -f integration/admission/release-policy.json \
  -f integration/admission/attestations-policy.json
kubectl --kubeconfig /absolute/path/to/kubeconfig apply -f examples/admission/namespace.json
kubectl --kubeconfig /absolute/path/to/kubeconfig create --dry-run=server \
  -f examples/admission/pass-pod.json -o json
```

The signed fixture should be admitted only after both policies are effective. The full negative-fixture replay uses `make admission` so its temporary key trust and registry never enter an existing cluster. Namespace enrollment and cluster-wide policy changes require administrator control. Admission checks new/updated resources; it does not evict previously admitted Pods or guarantee image execution. Public registry/trust-service availability, one verifier replica and other operational limits in the [signature guide](admission-signatures.md) still apply.

## Executed results

The local run on 2026-10-25 (America/Vancouver) passed **30 cases in 30 API requests**, with **zero transition attempts**. The final decisions were 11 admissions, 5 missing-signature denials, 4 identity denials, 8 attestation denials, 1 no-policy denial and 1 fail-closed verifier-unavailable rejection. All **18 classification regressions** passed. The Go integration package completed in 66.335 seconds. The verifier recovered and admitted the trusted release again; the cluster, registry and fixture key directories were removed.

Request counts cover the recorded workload-admission attempts; setup, policy-management and API-discovery calls are excluded.

[Local structured evidence](evidence/admission-attestations-local.json) records every final case decision, timestamps, versions and tested-source/raw-evidence/fixture-inventory hashes. The [hosted quality run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40255328012) independently passed the same **30 final case decisions and 18 classification regressions** on Linux amd64, in **35 recorded admission requests**. Its Go integration package completed in 58.346 seconds. It also passed all existing quality gates and all 80 runtime network-policy probes. The [hosted evidence](evidence/admission-attestations-hosted.json) includes exact decisions, every transition, versions, timestamps, source/raw/fixture hashes and the retained artifact identity/digest. The earlier 16-case signature-only results remain historical evidence in the [signature guide](admission-signatures.md).

**Observed policy-update limit:** the hosted `wrong-workflow` case recorded **five admissions using the previous allowed decision** after the intentional signer-policy change; attempt 6 returned the expected identity denial. These are five transition attempts, not five immediate rejections. All new attestation-specific cases reached their expected decision on attempt 1. An acknowledged policy update does not atomically change all verifier state and cannot promise immediate revocation. Establish and verify the intended rules before enrolling/deploying workloads; protect updates and plan for their propagation. The suite records bounded convergence rather than concealing these requests.

Selected actual local output:

```text
attestation-complete: allowed (exit 0, attempt 1)
attestation-missing-sbom: attestation-denied (exit 1, attempt 1)
attestation-missing-evidence: attestation-denied (exit 1, attempt 1)
attestation-invalid-sbom: attestation-denied (exit 1, attempt 1)
attestation-tampered-evidence: attestation-denied (exit 1, attempt 1)
attestation-wrong-subject-evidence: attestation-denied (exit 1, attempt 1)
release-requirements-restored: allowed (exit 0, attempt 1)
```

The missing-SBOM request explicitly reported `failed policy: release-attestations` and `no matching attestations with type https://cyclonedx.org/bom`, while identifying the evidence predicate as present. The missing-evidence request reported the reverse. The signed empty-component SBOM failed the `list.MatchN` content constraint. Those are verifier decisions, not missing-image or transport failures. Both production content rules also passed independent CLI verification against the actual public release with normal certificate/transparency checks. The final local replay also passed with `COSIGN_REPOSITORY=invalid.invalid/disallowed` set; fixture preparation clears that inherited override, confining its writes to the temporary registry.

Reference: [upstream policy and attestation semantics](https://docs.sigstore.dev/policy-controller/overview/). The committed tests and structured execution records establish this project's results.
