# Threat model

## Scope and assets

Protect the published image, dependency and tool inputs, release identity, inventory/evidence, and the cluster workload's isolation. Assume an attacker can submit a pull request, alter a mutable image tag, provide unexpected manifests, publish a vulnerable dependency, or exploit an HTTP parser bug. Assume trusted maintainers, the protected source branch, runner isolation, cryptographic roots, engine, cluster administrators and host kernel remain trusted. A maintainer who can change both policy and tests can change the rules.

| Attack path | Executable control | Regression / evidence | Remaining exposure |
| --- | --- | --- | --- |
| Mutable dependency or builder substitution | Index digest, tool checksums, exact Go version, zero external modules, offline compiler | `make test`; build metadata; `check-inputs.py` | Initial locks and upstream binaries must be trustworthy |
| Malicious pull request reads publishing credentials | Quality job has only contents read, no persisted checkout credential; publishing is tag-only and needs quality | Workflow guard and actionlint | Runner or trusted workflow compromise |
| Vulnerable standard library reaches release | Fresh database, complete versioned Go inventory, HIGH/CRITICAL/unknown severity blocking | Real before/after compiler remediation; synthetic negative tests | Unknown vulnerabilities and scanner coverage gaps |
| Broad or expired suppression hides risk | Exact ID/package/version/digest, owner, evidence, 14-day expiry; critical never excepted | Exception regression cases | Evidence quality and acceptance still require human review |
| Malicious chart gains host or credential access | Non-root, read-only root, no escalation/capabilities/token/host namespaces; no added containers/mounts; restricted admission | Chart mutations, runtime diagnostics, privileged-pod denial | Gate is scoped to this chart, not arbitrary resources |
| Workload pivots to adjacent services | Namespace-local TCP ingress and deny-all egress NetworkPolicy | Rendered rule/selector mutation tests | Default local CNI does not enforce NetworkPolicy; production CNI enforcement must be tested |
| Registry tag or artifact is changed | Digest references, exact release certificate identity and issuer, signed SBOM/evidence | Hosted verification; local SBOM tamper test | Tags and unsigned staged images still exist; consumers must verify |
| Build embeds time or filesystem paths | Trimpath, VCS metadata disabled, empty build ID, fixed epoch and rewritten layer timestamps | Two uncached matching manifest digests | This is a same-environment reproducibility check, not an independent rebuild attestation |
| HTTP exhaustion or runtime exploit | Header/request/response timeouts, bounded headers, CPU/memory/PID limits, seccomp runtime default | HTTP tests and real runtime checks | Kernel bugs, volumetric traffic, and downstream ingress configuration |

## Security boundaries and non-goals

The service accepts no user-managed files, credentials, commands or outbound URLs. It exposes plain HTTP inside the cluster; terminate TLS at a separately configured ingress if needed. It does not implement authentication, tenant isolation or a general policy framework. Fixed public responses have no protected business data.

The release signing identity is the exact repository workflow at an exact version tag, issued through the hosted workflow OIDC issuer. Verification never uses a wildcard identity and never disables transparency checks in the release path. The separate local-key exercise verifies byte integrity only and explicitly skips transparency validation.

No cluster admission signature verifier is installed. A verified digest can still be replaced by an administrator who changes the Deployment. NetworkPolicy is additive across policies; additional policies or namespace peers may broaden effective access. Cluster administrators, the CNI, kubelet and kernel remain outside the chart's control.

No VEX is emitted. A small image, lack of a shell, or lack of a direct function call is insufficient evidence for a not-affected assertion. The implemented exception mechanism records temporary risk acceptance, not exploitability status.
