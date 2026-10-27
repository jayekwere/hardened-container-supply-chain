# Maintenance and control-plane failure controls

The installer includes an inactive API-server maintenance gate and two verifier replicas. The verifier binary and signed `controller-v0.1.1` image are unchanged. These deployment and operating controls address the earlier single-verifier failure and provide a deliberate pause for multi-policy changes or migration from older verifiers.

## Workload maintenance gate

`integration/admission/maintenance-policy.json` installs a `ValidatingAdmissionPolicy` with `failurePolicy: Fail` and a binding with `validationActions: [Deny]`. It rejects CREATE and UPDATE for built-in workloads in namespaces labelled `supply-chain.example.invalid/maintenance=locked`. Coverage includes Pod ephemeral-container and resize updates and controller scale subresources. It does not call the external verifier. Status updates, deletion and cluster-scoped policy administration remain available. Custom controllers can still accept their own configuration, but their resulting Pod creations are blocked.

The label and policy are administrator-controlled. Tenants must not have permission to change namespace labels, admission policies/bindings, verifier deployment/routing or trust policies. This is a maintenance control, not a new authorization boundary against a cluster administrator. Gate installation and namespace-label propagation are asynchronous. Confirm actual denials on every serving API before beginning a trust change.

For the dedicated sample namespace, using administrator kubeconfig files that each address one API server directly:

```sh
export PATH="$PWD/.tools/bin:$PATH"
kubectl --kubeconfig /path/api-1.conf apply -f integration/admission/maintenance-policy.json
kubectl --kubeconfig /path/api-1.conf label namespace signature-demo \
  supply-chain.example.invalid/maintenance=locked --overwrite
for config in /path/api-1.conf /path/api-2.conf /path/api-3.conf; do
  # Expect rejection naming hsc-maintenance and HSC-MAINTENANCE.
  kubectl --kubeconfig "$config" create --dry-run=server \
    -f examples/admission/pass-pod.json
done
```

An arbitrary error does not prove the gate is active. Each probe must have succeeded before locking, then return the maintenance-specific rejection. Use real, CA-verified API endpoints; three files pointing to one load balancer are not three independent confirmations. The automated replay addresses each API through its own node loopback with that node's administrator configuration.

After confirmation, stop workload-writing automation and drain outstanding requests according to the API server's actual request timeouts and observed in-flight activity. Then apply the reviewed policy changes. Keep the namespace locked on any error. There is deliberately no automatic unlock in a shell exit trap.

```sh
python3 scripts/apply-bootstrap-policy.py /path/api-1.conf integration/admission/release-policy.json
python3 scripts/apply-bootstrap-policy.py /path/api-1.conf integration/admission/attestations-policy.json
# After verifying the resulting policy specs, current verifier fleet and intended
# trust profile, explicitly resume workload writes.
kubectl --kubeconfig /path/api-1.conf label namespace signature-demo \
  supply-chain.example.invalid/maintenance-
for config in /path/api-1.conf /path/api-2.conf /path/api-3.conf; do
  kubectl --kubeconfig "$config" create --dry-run=server -f examples/admission/pass-pod.json
  # Expect signature rejection, never successful admission.
  kubectl --kubeconfig "$config" create --dry-run=server -f examples/admission/fail-pod.json
done
```

The example policies restore the checked release trust; review replacements before applying a different identity. For migration, verify the signed verifier release first, update the installation using the checked values and explicit digest, and retire every old verifier process and established connection before unlocking. Pod readiness or endpoint removal alone does not prove process termination on a failed node; confirm it through the relevant node/runtime boundary. The maintenance gate cannot recall a request already approved before activation, make policy writes transactional with object persistence, or evict existing Pods. It bounds operator-controlled transitions after observation and draining; it does not remove the final read-to-write race.

## Verifier placement and disruption

The checked Helm values require two replicas on distinct hostnames within the same Deployment revision, using required Pod anti-affinity and `pod-template-hash` matching. At least two eligible nodes are required. A disruption budget retains one available replica for voluntary disruptions. Rolling updates allow one unavailable replica and no surge; matching by revision lets a replacement revision schedule while an older process drains. The chart's existing drain grace period is retained. The installer allows up to ten minutes for startup/rollout rather than shortening graceful shutdown to make a check pass.

```sh
kubectl --kubeconfig /path/api-1.conf -n image-policy-system get pods \
  -l app.kubernetes.io/instance=policy-controller -o wide
kubectl --kubeconfig /path/api-1.conf -n image-policy-system get deployment,poddisruptionbudget
```

Inspect actual ready Pod placement and effective values. A disruption budget does not prevent involuntary node failure or protect against administrative replica changes. Required anti-affinity applies at scheduling time; it does not evict a Pod after label changes. Old and new revisions can temporarily share a hostname, and a rolling update plus another failure can still make admission unavailable. Fail-closed rejection remains the safety behavior.

## Failure replay

```sh
make test
make admission
```

The disposable replay verifies two ready verifiers on separate nodes, then tests complete verifier-node loss, suspension of the measured current etcd leader, and loss of two of the three etcd voters while one verifier/API remains alive. Member IDs and leaders are read from each local etcd container with certificate verification. A leader-change result requires a different leader reported by both survivors. Quorum-loss controls require a real storage-write availability failure and rejection of a correctly signed admission request, followed by successful valid/invalid controls after restoration. Every paused node resumes during cleanup.

`availability.json` and `maintenance.json` retain individual requests, timestamps, placement, member/leader IDs and gate confirmations. Any unexpected admission in a required-negative probe fails immediately. Recovery may retry only an observed availability/freshness failure, retaining every attempt; a timeout never counts as a signature denial. The existing trust-update, SBOM/evidence, image-signature and NetworkPolicy suites remain active. Admission outputs are cleared at the start of each replay, and `run-selection.json` records whether a run selected the full suite or focused tests. A focused rerun, such as `TEST_ADMISSION_RUN='^(TestAdmissionSignatures|TestMaintenance|TestTrustUpdates)$' make admission`, is not a full-suite result.

The draining-process trust replay starts a new Deployment revision while a warmed process terminates. Revision-scoped anti-affinity permits the replacement to schedule without changing the retiring Pod's labels or affinity. Its established direct TLS connection remains active so the tightened policy is also tested against that older process.

## Recorded results

The [initial local candidate](evidence/operations-initial-local.json) ran on Linux arm64 with Kubernetes v1.34.0 and the unchanged native verifier image. Its **full integration invocation failed** in **512.396 seconds**; it is not reported as a passing full suite.

| Initial candidate control | Observed result |
| --- | --- |
| Node loss, measured leader loss, quorum loss and restoration | 34 logical controls in 44 requests; 16 intended admissions, 16 signature denials, 10 transient webhook-unavailable responses and 2 quorum-loss availability rejections; zero unexpected admissions |
| Availability test duration | 222.25 seconds |
| Forced election | All three members reported the old leader at term 3; both survivors reported a different leader at term 4 |
| Original signature/attestation matrix | 30 cases in 31 requests; recovery first failed closed, then admitted |
| Isolated API/etcd-node outage | 16 logical controls in 20 requests; 8 intended admissions, 8 signature denials, 1 unavailable response and 3 freshness denials before recovery |
| Maintenance test | Failed after 25 observations because the delete cleanup probe requested unsupported JSON output; that command did not reach admission |
| Trust-update test | Failed after 58 observations when the same-revision replacement could not schedule beside a draining process; no unexpected admission occurred |

The delete probe now uses the supported name output. The replacement test now creates an actual Deployment revision, preserving the old process and its TLS connection while allowing the revision-scoped placement rule to work. Neither correction relaxes a required policy rejection or the placement constraint.

The [focused local replay](https://github.com/jayekwere/hardened-container-supply-chain/releases/download/controller-v0.1.1/operations-focused-local.json) records the corrected signature, maintenance and trust-update suites. It is explicitly scoped and does not claim to repeat the longer fault suite. The [full hosted replay](https://github.com/jayekwere/hardened-container-supply-chain/releases/download/controller-v0.1.1/operations-hosted.json) records final-source results, exact counts, runtime image identity, source/raw-output hashes and workflow/artifact identity. Required quality checks execute the full suite before merge. These records remain separate; partial runs are not combined into an invented passing full local run.

Supplementary raw operating evidence is attached to the same [verifier release](https://github.com/jayekwere/hardened-container-supply-chain/releases/tag/controller-v0.1.1). These later files are not authenticated by the earlier build-evidence attestation. The original published-digest release run and its scan/signature/SBOM evidence remain unchanged. Native local image identity and hosted engine-import identity are recorded separately from that published-digest run.

The [October 27 recovery replay](failover-recovery.md) adds separate-node DNS placement in the disposable cluster, a full verifier/DNS/endpoint recovery barrier between faults, exact client-timeout classification and diagnostics captured at the failure point. Its complete local results are recorded separately from the earlier release evidence.

## Limits that remain

These are single-host containerized nodes. They establish behavior for the recorded faults, not independent physical failure domains, arbitrary network partitions, sustained production load or zero downtime. Quorum loss is deliberately unavailable. API consistency, namespace enrollment, administrator authority, node/runtime integrity, the build host and initial verifier trust remain boundaries. Unsupported mutable trust references remain rejected; no general upstream compatibility claim is added. Scans remain dated inventories, and later runtime results are not authenticated by the earlier build attestation. Existing published results and availability failures remain historical evidence.

References: [API-enforced admission policies](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/), [revision-aware Pod affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#matchlabelkeys).
