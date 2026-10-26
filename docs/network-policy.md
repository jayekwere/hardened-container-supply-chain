# Runtime network-policy verification

The two-node local and hosted runs on 2026-10-25 (America/Vancouver) each passed **80 real traffic probes with zero mismatches**: **160 total**, including 60 expected timeouts and 100 successful connections/queries. Policy application blocked the five prohibited flows; policy removal restored them; reapplication reproduced the denials. This extends the earlier release's static checks with runtime evidence.

## Reproduce

From the repository root, with a running engine that supports privileged disposable kind nodes:

```sh
make tools
make test
make cluster
```

`make cluster` creates a control-plane node and a worker, installs the digest-pinned policy agent, waits for both agent instances and DNS, loads the unchanged application image, and deploys the unchanged Helm chart. It runs the original workload checks plus the traffic matrix, writes evidence, and removes the cluster and its private kubeconfig on success or failure. It never selects an existing cluster.

Evidence is written to `artifacts/cluster/network-policy.json`, `tests.txt`, `nodes.json` and `enforcer.json`. Failure diagnostics are also retained. The quality workflow runs the same command and uploads these files with its normal evidence retention.

```sh
python3 - <<'PY'
import collections, json
from pathlib import Path
run = json.loads(Path('artifacts/cluster/network-policy.json').read_text())
print(run['Outcome'], len(run['Observations']))
for phase in ['baseline', 'enforced', 'restored', 'reapplied']:
    rows = [r for r in run['Observations'] if r['Phase'] == phase]
    print(phase, dict(collections.Counter(r['Result']['outcome'] for r in rows)))
PY
```

Observed output:

```text
passed 80
baseline {'reachable': 10}
enforced {'reachable': 15, 'timeout': 15}
restored {'reachable': 10}
reapplied {'reachable': 15, 'timeout': 15}
```

The [committed local summary](evidence/network-policy-local.json) includes timestamps, kernel/runtime versions, source-file hashes and the SHA-256 of the full raw observations. The [hosted quality run](https://github.com/jayekwere/hardened-container-supply-chain/actions/runs/40248892351) also passed all gates. Its [committed summary](evidence/network-policy-hosted.json) records the artifact ID/digest and exact source revision. Both environments produced the same per-phase counts shown above.

## Traffic matrix

All HTTP probes request `/healthz` over TCP 8080 and require status 200 with the exact body `ok\n`. DNS probes send a real UDP port 53 query for `kubernetes.default.svc.cluster.local`, validate its transaction ID and require a successful answer.

| Flow | Policy absent | Policy enforced | Policy removed | Policy reapplied |
| --- | --- | --- | --- | --- |
| Same-namespace peer → workload pod IP | Reachable | Reachable | Reachable | Reachable |
| Same-namespace peer → workload Service IP | Reachable | Reachable | Reachable | Reachable |
| Other-namespace peer → workload pod IP | Reachable | Timeout | Reachable | Timeout |
| Other-namespace peer → workload Service IP | Reachable | Timeout | Reachable | Timeout |
| Workload → same-namespace peer | Reachable | Timeout | Reachable | Timeout |
| Workload → other-namespace peer | Reachable | Timeout | Reachable | Timeout |
| Workload → cluster DNS (UDP 53) | Reachable | Timeout | Reachable | Timeout |
| Unselected same-namespace peer → other peer | Reachable | Reachable | Reachable | Reachable |
| Unselected same-namespace peer → DNS | Reachable | Reachable | Reachable | Reachable |
| Unselected other-namespace peer → local peer | Reachable | Reachable | Reachable | Reachable |

Baseline and restoration each require one successful round across all ten flows. Enforcement and reapplication each require **three consecutive** rounds, giving 10 + 30 + 10 + 30 = 80 observations in the recorded run. The harness allows bounded policy convergence and records every attempt; extra convergence attempts would increase the observation count and remain visible in raw evidence. No extra attempts were needed in either recorded run.

## Why the negative results are meaningful

The workload runs on the worker. The same-namespace peer runs on the control-plane node; the other-namespace peer runs on the worker. The matrix therefore includes same-node and cross-node packet paths. Peer pods use the same digest-pinned application image, restricted pod settings and explicit readiness probes, with labels that do not match the workload policy or Service selector.

The test client is a separate Go executable built only for testing. The runner discovers each pod sandbox PID through the node's container runtime and executes the client with `nsenter --net` inside that exact network namespace. The client verifies the expected pod IP is present and explicitly binds its socket to that IP. HTTP targets use literal pod/Service IPs, so HTTP failures cannot be explained by a DNS block. This is actual pod-network traffic, not an API-server port-forward. The application image and Deployment receive no test client, debug container or writable mount.

Every attempt uses a fresh TCP connection or UDP socket. HTTP connection reuse, ambient proxies and redirects are disabled. A missing namespace, failed command, refused connection, invalid response or other client error is an infrastructure/application failure, **never** a passing policy denial. Only the client's bounded network-timeout exit code 10 can satisfy a denied-flow expectation.

Allowed HTTP flows keep checking the workload and both peer servers while denied flows run; an unselected peer keeps checking DNS. All ten flows must work before policy application and again after policy removal. These controls distinguish policy filtering from dead servers, broken routing, failed DNS, stale connections or an incorrectly entered namespace. Reapplication must then reproduce the result. Unit regression cases also reject a missing-enforcer traffic leak, a namespace mismatch, contradictory exit codes and a failed positive control.

The policy is read from the installed chart, removed and restored with the same specification. A cleanup handler restores it if a phase fails; the outer runner then removes the entire disposable cluster.

## Dependency and trust boundary

The test keeps kindnet for connectivity and adds `kube-network-policies` v1.1.2 for enforcement. Its multi-platform image is pinned to `sha256:c671f98e444825d57c590c92da1b5e66070917c4d3dff1f9279775e6b73254fe`. The [lock](../integration/network-policy/enforcer.lock.json) records the exact upstream commit. The committed [manifest](../integration/network-policy/enforcer.json) explicitly selects the patched image; the upstream tagged example still selected v1.1.1.

The node-level policy agent needs privileged networking access, NRI/network-namespace mounts, and list/watch access to pods, namespaces and NetworkPolicies. It runs only in the disposable test cluster's system namespace. It is not an application chart resource, and no extra workflow token permissions are granted. Runtime instrumentation likewise requires administrator access to those disposable nodes; it does not grant those capabilities to the workload.

The local run used two Linux arm64 nodes, Kubernetes v1.34.0, containerd 2.1.3 and kernel 6.12.76-linuxkit. The hosted run used two Linux amd64 nodes, the same Kubernetes/runtime versions and kernel core version 6.17.0; its summary stores a hash of the complete kernel release identifier. Local workload digest: `sha256:a1fe6ec5772948818f8e52ddbfcb198865bb49fd4d68b36c1607a2feaaf88330`. Hosted workload digest: `sha256:e0b4773135955a2d269f5f241771ede7c4fb3a47d37896af175aae8f8e7efe22`, matching the published application image.

Reference setup: [upstream kind quick start](https://kube-network-policies.sigs.k8s.io/docs/quick-start/). The project uses a committed, digest-pinned fixture rather than applying the mutable upstream branch.

## Scope

This proves the recorded IPv4 TCP 8080 and UDP DNS 53 flows for the selected agent, topology and kernel. It does not prove every protocol/port, IPv6, every CNI, node/host-network isolation, application authorization, or the behavior of a different production cluster. Additional policies are additive and may broaden access. A deployment using another enforcement implementation should run equivalent positive, negative and restoration checks there.

The earlier `v0.1.1` release evidence is historical and remains accurate about what was tested when it was created. These new tests add verification without changing that release's application image or chart.
