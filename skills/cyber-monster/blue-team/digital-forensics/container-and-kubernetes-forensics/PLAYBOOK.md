# Operational Triage and Response Playbook

> Sub-skill: [`container-and-kubernetes-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `container-and-kubernetes-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

Containment in a cluster is fast, reversible and destructive: a deleted pod is gone in seconds and takes its writable layer, its process state and often its only log with it. The runbook therefore sequences capture before cordon, and cordon before delete, and it always records whether audit logging was on — because a cluster without audit cannot answer the questions this skill exists to answer, and a report that omits that fact is misleading even when every command was correct.

## Triggers

- Alert, hunt outlier, or review request matching `container forensics`.
- Alert, hunt outlier, or review request matching `kubernetes forensics`.
- Alert, hunt outlier, or review request matching `container image analysis`.
- A runtime-security alert names a pod, image or service account, and the question is what that workload actually executed.
- A pod's resource usage, outbound connections or mounted secrets change without a corresponding deployment.
- A cluster node is found running a workload not present in any expected manifest.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `exec` subresource with `code: 101` by a workload service account | Confirmed interactive access | Freeze the pod YAML, capture the node snapshot directory, then scope what the token could read |
| `patch` on `ephemeralcontainers` by an identity not in the operator baseline | Confirmed inspection injection | Capture the injected image reference and the follow-on `attach`; treat mounted secrets as exposed |
| `get`/`list` on secrets by a workload identity at a rate above its baseline | Confirmed credential access | Preserve the audit range; rotate every secret that identity could read, then check for its use elsewhere |
| Writable overlay layer with files newer than the image tag's build time | Anomalous write | Hash the files and record their mount source before attributing; a PVC or `emptyDir` changes the meaning |
| Pod deleted before capture, node not yet recycled | Partial recovery | Image layers, `/var/log/pods` and audit log only; state that the writable layer is lost |
| Node recycled and content store garbage-collected | Inconclusive (Evidence Lost) | Audit log and PV data only; record the GC and node-lifetime facts that made this unrecoverable |
| Audit policy excluded the involved resources or was disabled | Inconclusive (Telemetry Gap) | Do NOT close as clean; open a control-remediation action for audit policy coverage |

## Containment and Recovery

1. **Preserve before mutating:** capture pod YAML, Events, the audit window, the node's snapshot directories and `/var/log/pods` before cordoning. Cordon and drain come after, and deletion only after that — never before.
2. **Do not exec into a suspect container.** Use an ephemeral debug container, and record that you did so, because your own `ephemeralcontainers` patch will appear in the audit log next to the adversary's.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and in cluster terms, never drain a node running the ingress controller, CNI or DNS add-on without the platform owner's agreement.
4. **Scope by identity, then by node:** a compromised service account means every secret it could read is exposed, and every node that token was used from is in scope. Collect the token's audit history before rotating, or you lose the only record of where it was used.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the vector was an over-permissive RBAC binding or a mutable image tag, fix the binding or pin the digest and re-derive which other workloads share it — a single-pod fix leaves the rest of the cluster exposed.
