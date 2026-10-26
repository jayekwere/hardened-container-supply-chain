# Patched verifier release and multi-control-plane checks

The verifier is a separate artifact from the sample application. Both use the existing public OCI repository, with independent digests, release tags and workflow identities; the verifier uses `controller-v*` tags. Its build uses the checksum-locked source archive, the authoritative-read patch and a checked-in dependency patch. The dependency patch records the complete resulting module and checksum changes; normal builds use `-mod=readonly` and `go mod verify`. The root application module remains dependency-free.

The initial verifier scan found 52 findings: 27 HIGH, 21 MEDIUM, two LOW and two UNKNOWN. The existing gate rejected that image with 29 blocking reasons. [Pre-remediation evidence](evidence/verifier-pre-remediation.json) records the inventory, exact versions, build identity and scan hash. That initial gate used no VEX or suppression. Dependency upgrades removed 51 findings. One UNKNOWN advisory remains in the raw report: `GO-2026-5932`, scoped to the `golang.org/x/crypto/openpgp` package family. The release gate handles only this finding through the bounded VEX control below; it does not claim a zero-finding raw scan.

## Reproduce the controls

```sh
make tools
make test
make controller-image
./scripts/scan-controller.sh
make admission
```

`make admission` creates three control-plane nodes with three API servers and three etcd members. Only this disposable cluster has its node scheduling taints reset; the third node is then reserved for API/etcd processes and cannot schedule the verifier. Probes run `kubectl` inside each named node with that node's admin configuration, CA verification and `--server=https://127.0.0.1:6443`. This bypasses the external API load balancer. No admin credentials are printed or exported from the nodes.

The original signature/attestation matrix remains active. Trust-update probes now exercise each API server individually as well as CA-verified connections to selected verifier Pods. After deliberate compiler-write failures, restoration confirms write permission and uses metadata events to requeue finalizer cleanup; it never removes finalizers administratively. The suite freezes compiled-policy publication, poisons its older copy, tightens signer and attestation trust, removes authoritative-read permission, deletes/recreates a mandatory policy and adds a restrictive policy. Any unexpected admission fails immediately. Separate passing/failing probes cover all three APIs, a suspended control-plane node and restoration. Transient fail-closed errors during availability recovery are retained as additional observations; they cannot count as a successful signature rejection.

The suspension case proves the verifier is on another node, pauses the complete third control-plane container including its API and etcd member, then resumes it in cleanup. Requests target the other two APIs directly. An initial co-location experiment did fail its availability expectation: the verifier on the paused node became unreachable and the request failed closed with a TLS handshake timeout. [That failed experiment is preserved](evidence/verifier-combined-node-outage-local.json); it is excluded from passing counts. Simultaneous verifier-node loss is not covered by the isolated API outage availability claim. Verifier-process loss is tested separately as a fail-closed outage. This is a single-host, disposable-cluster exercise; it does not establish behavior during arbitrary partitions, quorum loss, regional failures or production load.

## Release gates and verification

The `controller-release.yml` workflow runs for `controller-vMAJOR.MINOR.PATCH` tags. Publication is limited to the named repository and commits reachable from reviewed `main`. Quality checks have read-only permissions. The publishing job alone receives package-write and short-lived identity permissions; the record job alone receives content-write permission. Actions are pinned to complete commit hashes and checkout does not retain credentials.

The release build targets Linux amd64, independently recompiles the verifier with `go build -a`, compares binary bytes and runs focused regression tests. A fresh vulnerability database is mandatory. After the bounded VEX evaluation, the unchanged generic scan policy rejects remaining HIGH, CRITICAL and UNKNOWN findings. This verifier release profile requires an empty exception ledger. An outdated database or failed scan stops publication. The exact archive manifest is copied with ORAS and its registry digest must match before signing.

The image signature, CycloneDX SBOM and custom evidence predicate all use the exact workflow identity:

```text
https://github.com/jayekwere/hardened-container-supply-chain/.github/workflows/controller-release.yml@refs/tags/controller-vMAJOR.MINOR.PATCH
```

The issuer is `https://token.actions.githubusercontent.com`. Normal certificate and transparency verification remain enabled. Evidence type `https://github.com/jayekwere/hardened-container-supply-chain/verifier-evidence/v1` is a project-defined statement, not an external certification. It binds source revision, upstream source/archive, both patches, compiler, binary, module files, scan/SBOM/database files, focused test output and independent-recompilation output to the image digest.

```sh
git fetch origin --tags
# Set these from the selected release's image-reference.txt and tag.
: "${CONTROLLER_IMAGE:?digest-addressed verifier required}"
: "${CONTROLLER_TAG:?controller release tag required}"
./scripts/verify-controller-release.sh "$CONTROLLER_IMAGE" "$CONTROLLER_TAG"
# Download that release's assets into artifacts/controller before checking reports.
./scripts/verify-controller-release.sh "$CONTROLLER_IMAGE" "$CONTROLLER_TAG" artifacts/controller
TEST_RELEASE_CONTROLLER_IMAGE="$CONTROLLER_IMAGE" \
TEST_RELEASE_CONTROLLER_TAG="$CONTROLLER_TAG" make admission
./scripts/install-admission.sh /absolute/path/to/kubeconfig "$CONTROLLER_IMAGE"
```

Verification checks the tag's commit, digest subjects, exact workflow identity, expected source/patch hashes and claim profile. With downloaded assets supplied, it compares their bytes with the authenticated evidence hashes. Release regressions require both a wrong workflow identity and changed SBOM report bytes to reject. These are separate from the 15 synthetic claim mutations. Post-publication admission tests pull the exact signed digest onto fresh cluster nodes. A failed post-publication test prevents a release record, but cannot retract an image/signature already published; inspect the workflow outcome and attached runtime evidence before adopting a release.

## Bounded VEX evidence

The advisory's authoritative JSON is checksum-locked in `security/verifier-vex.lock.json`. Every build enumerates the full target-specific Go import closure for `./cmd/webhook` using the same compiler, module files, CGO setting, OS and architecture as the binary. The VEX evaluator checks that the advisory affects only OpenPGP packages and that none of those packages or subpackages is compiled. A changed advisory checksum/scope, missing inventory, affected import, duplicate finding or unexpected module blocks the gate.

Only the exact advisory/module/version finding is removed from a separate `scan-policy-input.json`; `scan.json` and the SBOM remain unchanged. Every other finding, including other UNKNOWN findings, reaches the original policy. `vex.json` uses OpenVEX status `not_affected` with justification `vulnerable_code_not_present` and a product identifier bound to the image manifest. `vex-evidence.json` records binary, architecture, closure count/hash, advisory hash and the original finding. These files, the package list, authoritative advisory and filtered policy input are authenticated by hashes in the signed evidence attestation. The VEX document has no separate signature.

Eight negative regressions require rejection when scope, compiled packages, checksum, module, architecture or inventory becomes unsafe. An additional unrelated UNKNOWN fixture is explicitly retained for the normal gate. This is package absence evidence, not a claim that vulnerable linked code is unreachable. The compiler and build host remain trusted; no general automatic VEX engine or arbitrary exception facility is provided.

References: [authoritative advisory](https://vuln.go.dev/ID/GO-2026-5932.json), [OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).

## Remaining boundaries

The verifier itself is installed by a trusted administrator; it cannot establish its own initial admission trust. Verify its release before installation. Existing unpatched verifier processes must all terminate during migration. Application admission still requires its independent signature and both application attestations.

Two authoritative reads are not a transaction with eventual object persistence. Existing approvals and running Pods are not recalled; multi-policy writes are not atomic. Mutable trust references and unsupported modes remain intentionally rejected. API availability, administrator-controlled enrollment/routing and node integrity remain trusted. A scan is a database snapshot and module inventory, not a proof that every possible defect is absent. The focused verifier tests do not claim execution of the complete upstream suite.

## Executed local results

The final local run on 2026-10-26 used Linux arm64 nodes and the dependency-patched verifier. `make admission` and the subsequent verifier scan exited 0. The Go integration package completed in **185.062 seconds**. [Structured local evidence](evidence/verifier-multi-local.json) records image/binary identity, all phase counts, source/raw-output hashes, policy-write acknowledgements and normalized platform details.

| Local check | Exact outcome |
| --- | --- |
| Trust updates | 183 probes: 31 intended admissions, 152 required denials, zero unexpected admissions |
| API coverage | 38 individually addressed probes per API server, plus 3 Deployment-update probes through the load balancer: 117 API requests total |
| Direct verifier coverage | 66 CA-verified TLS probes across 3 distinct Pods during replacement |
| Frozen/poisoned compiled copy | 25 unsigned-image signature denials |
| Signer tightened after acknowledged write | 25 identity denials |
| Attestation trust tightened after acknowledged write | 25 identity denials |
| Authoritative-list permission removed | 25 freshness denials; all 3 outside-scope controls admitted |
| Mandatory attestation policy deleted | 25 freshness denials; recreation restored admission |
| Restrictive policy added | 25 explicit policy denials; removal restored admission |
| Replica reduction variants | Unchanged object admitted; changed image and changed label each denied |
| Isolated API/etcd node pause | 16 controls: 8 valid admissions and 8 signature denials; no transient retries |
| Existing signature/attestation matrix | 30 cases in 31 requests; recovery first failed closed, then admitted on attempt 2 |
| Focused verifier tests | 29 leaf cases passed; complete upstream suite not claimed |
| Admission classification | 24 cases passed |
| Claim validation | Valid claim set accepted; 15 changed sets and missing reports rejected |
| VEX validation | Valid bounded case accepted, unrelated UNKNOWN retained, 8 unsafe mutations rejected |
| Prepared source cache | Changed source rejected; original bytes restored and accepted |
| Scan/SBOM | 0 HIGH, 0 CRITICAL, 1 retained raw UNKNOWN; bounded VEX passed; 2,048 compiled packages; 276 SBOM components |
| Root unit/race checks, actionlint and workflow guard | Exit 0 |

The local imported image was `docker.io/library/supply-policy-controller@sha256:b1d41fd9788b66b6d1c248c24495b310c20143235ad8fceb55d36b5a071cd441`; the running container reported that same manifest. This local reference is distinct from the Linux amd64 registry release. Its independent-recompilation step was explicitly skipped locally and is a release-only gate. The disposable cluster and fixture registry were removed.

The paused etcd member's leadership was not selected, so these controls do not constitute a forced etcd-leader failover test. No arbitrary partition, quorum-loss, sustained-load or independent-host availability result is claimed.

## Bootstrap readiness

The initial `controller-v0.1.0` workflow failed closed before publication: the policy webhook briefly refused a connection after chart readiness. Both publish and release-record jobs were skipped; that tag has no supported image release. [Failure evidence](evidence/verifier-bootstrap-failure.json) preserves the exact cause and run.

The installer now retries only an unavailable ClusterImagePolicy webhook during initial policy installation. Attempts are recorded in `artifacts/admission/bootstrap-*.json`, limited to ten attempts and a 60-second retry window with bounded individual requests. A real policy denial, foreign webhook or process error stops immediately. The workload admission tests retain immediate failure for any unexpected admission. Eight policy-apply regressions cover refusal/recovery, conversion EOF/recovery, validation EOF/recovery, genuine denial, denial quoting a network error, foreign webhook, persistent outage and execution timeout. Twelve Go regressions cover conversion-error classification, recovery, retry exhaustion and the prohibition on workload retries.

A parallel main-branch run also failed before acknowledging a policy update because a conversion-webhook connection closed while a verifier drained. Administrative policy applies now record and retry only transport failures from the known policy conversion, defaulting and validation endpoints, before declaring acknowledgement; all subsequent security probes still start after a confirmed write. `policyWriteAttempts` in the raw evidence retains every administrative attempt. Workload probes are unchanged and never retried after an unexpected admission. The policy-apply helper also handles this conversion error for operator commands.
