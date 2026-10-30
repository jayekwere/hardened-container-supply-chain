# Patched verifier release and multi-control-plane checks

The verifier is a separate artifact from the sample application. Both use the existing public OCI repository, with independent digests, release tags and workflow identities; the verifier uses `controller-v*` tags. Its build uses the checksum-locked source archive, the authoritative-read patch and a checked-in dependency patch. The dependency patch records the complete resulting module and checksum changes; normal builds use `-mod=readonly` and `go mod verify`. The root application module remains dependency-free.

The October 30 [scheduled-check review](quality-maintenance.md) upgrades two dependencies after new findings. Release-specific counts and scans below describe their dated source revisions. Historical release verification requires that tag's source checkout because the signed evidence binds both patch hashes; a different dependency patch must reject.

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

The later [maintenance and failure controls](operations.md) provide an API-enforced workload pause and expanded node/leader/quorum tests. The release-specific results below remain unchanged historical observations.

The verifier itself is installed by a trusted administrator; it cannot establish its own initial admission trust. Verify its release before installation. Existing unpatched verifier processes must all terminate during migration. Application admission still requires its independent signature and both application attestations.

Two authoritative reads are not a transaction with eventual object persistence. Existing approvals and running Pods are not recalled; multi-policy writes are not atomic. Mutable trust references and unsupported modes remain intentionally rejected. API availability, administrator-controlled enrollment/routing and node integrity remain trusted. A scan is a database snapshot and module inventory, not a proof that every possible defect is absent. The focused verifier tests do not claim execution of the complete upstream suite.

## Initial completed local replay

The initial completed local run on 2026-10-26 used Linux arm64 nodes and the dependency-patched verifier. `make admission` and the subsequent verifier scan exited 0. The Go integration package completed in **185.062 seconds**. [Structured local evidence](evidence/verifier-multi-local.json) records image/binary identity, all phase counts, source/raw-output hashes, policy-write acknowledgements and normalized platform details.

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

## Published release results

[controller-v0.1.1](https://github.com/jayekwere/hardened-container-supply-chain/releases/tag/controller-v0.1.1) completed the [release workflow](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40342659964), including all prerequisite quality gates, publication, signing, both attestations, negative verification tests and runtime checks against the exact registry image. The source revision is `02fcc679cf485c7f6231c94a399df6a97ed70699`.

```text
ghcr.io/jayekwere/hardened-container-supply-chain@sha256:59964fb24d115ce431a71a8d7c907788fea29a6ac855d306726a958c10c31f91
```

The registry manifest, independently built archive and observed running Pod image IDs all matched that digest. The earlier independently built amd64 quality archive also had this digest; its engine-imported runtime reference was different and remains separately recorded. The release build's forced second compilation produced a byte-identical binary. Published runtime nodes were Linux amd64 with Kubernetes v1.34.0. The Go integration package completed in **172.129 seconds**.

| Published-image check | Exact outcome |
| --- | --- |
| Trust updates | 183 probes: 117 API-server workload probes and 66 direct verified-TLS probes |
| Decisions | 31 intended admissions; 26 signature, 51 identity, 50 freshness and 25 additional-policy denials; zero unexpected admissions |
| Paused API/etcd node | All 16 logical controls passed in 18 requests: 8 valid admissions, 8 signature denials, 2 transient webhook-unavailable responses |
| Standard matrix | 30 cases in 31 requests; verifier recovery first failed closed, then admitted on attempt 2 |
| Policy administration | 17 standard-suite apply attempts; 6 trust-update writes used 7 attempts, including one conversion EOF before acknowledgement that recovered |
| Focused verifier / admission classification / policy-write regressions | 29 / 24 / 12 cases passed |
| Policy-apply / signed-claim / VEX regressions | 8 policy-apply cases passed; 15 claim mutations and missing reports rejected; 8 unsafe VEX mutations rejected |
| Release verification | Correct signature and both predicates accepted; wrong workflow identity and changed SBOM report bytes rejected |
| Anonymous consumer verification | Signature, both predicates, all 15 downloaded report checksums and decoded SBOM/evidence contents verified |
| Scan inventory | 276 SBOM components; 2,050 compiled packages; no HIGH or CRITICAL findings; one unchanged raw UNKNOWN with bounded VEX |
| Database | Updated 2026-10-26 14:38:04 UTC; downloaded 15:08:27 UTC before scanning |
| Risk-acceptance ledger | Empty |
| Application quality / real NetworkPolicy replay | All gates passed; 80 traffic probes, zero mismatches |

The two paused-node timeouts and the recovery rejection are availability failures, not cryptographic policy denials. The final expected controls then succeeded. The administrative EOF occurred before the confirmed policy-write acknowledgement; every attempt is retained, and no unexpected workload admission was retried into a denial. Counts exclude administrative, permission-check and snapshot-read requests.

[Published structured evidence](evidence/verifier-release-published.json) contains all phase counts, source/raw-output hashes, acknowledgement times, actual image IDs and artifact identity. [Independent anonymous verification](evidence/verifier-anonymous-verification.json) records the separate consumer check. Release assets preserve raw scan/SBOM/VEX files, module files, focused test output, authenticated build evidence, verification failures and individual runtime decisions. Later runtime results are separate assets; the earlier build-evidence attestation does not authenticate those later files.

## Verify the selected release

The checked [release lock](../integration/admission/verifier-release.lock.json) now selects the October 30 replacement. Require its completed release workflow and published assets before use. The counts above remain historical `controller-v0.1.1` results. For full report-byte verification, download the selected release's assets into a separate directory:

```sh
make tools
git fetch origin --tags
export CONTROLLER_IMAGE=$(python3 -c 'import json;print(json.load(open("integration/admission/verifier-release.lock.json"))["image"])')
export CONTROLLER_TAG=$(python3 -c 'import json;print(json.load(open("integration/admission/verifier-release.lock.json"))["tag"])')
./scripts/verify-controller-release.sh "$CONTROLLER_IMAGE" "$CONTROLLER_TAG"
# The optional asset-download command requires gh.
gh release download "$CONTROLLER_TAG" --repo jayekwere/hardened-container-supply-chain \
  --dir artifacts/downloaded-controller
./scripts/verify-controller-release.sh "$CONTROLLER_IMAGE" "$CONTROLLER_TAG" artifacts/downloaded-controller
```

The original `controller-v0.1.1` consumer check produced this output with its matching source:

```text
PASS signed verifier claims and downloaded report hashes
```

Verification uses the checked-out source/patch profile. Use a checkout of the selected release tag when verifying an older release after those inputs change. Published-digest runtime replay requires an amd64 engine; native arm64 replay uses `make admission` to build the corresponding local image. The anonymous cryptographic verification above runs on either supported client platform.

## Compiled-state evidence checks

The latest local replay additionally confirmed each temporary permission state through every API server and compared hashes of the compiled policy data through eight frozen phases. **All 18 authorization confirmations and all 8 snapshot comparisons matched**, alongside the same **183 trust probes, 16 outage controls and 30 standard cases in 30 requests**, with zero unexpected admissions. The integration package completed in **195.574 seconds**. [Structured local proof](evidence/verifier-compiled-state-local.json) binds these checks to source `e28194c`, the native arm64 image and raw evidence hashes. These additional checks do not change the verifier binary or the published image.

The [preceding readiness replay](evidence/verifier-readiness-hosted.json) passed the same trust/outage decision totals on the corrected source in 161.918 seconds, with no administrative retries and 30 standard requests. The [local readiness replay](evidence/verifier-readiness-local.json) passed in 209.618 seconds. Those dated records remain separate from the published-image run.
