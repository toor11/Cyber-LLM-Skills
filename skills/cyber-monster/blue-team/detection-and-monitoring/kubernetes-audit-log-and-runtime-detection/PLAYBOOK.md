# Operational Triage and Response Playbook

> Sub-skill: [`kubernetes-audit-log-and-runtime-detection`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `kubernetes-audit-log-and-runtime-detection`. Paired offensive/mechanics reference: [`kubernetes-pentesting`](../../../red-team/cloud-container-supply-chain/kubernetes-pentesting/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `kubernetes audit log detection`.
- Alert, hunt outlier, or review request matching `falco rule k8s`.
- Alert, hunt outlier, or review request matching `tetragon runtime`.
- Alert, hunt outlier, or review request matching `pods exec detection`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `exec` subresource accepted for a principal with no prior exec history, plus a Tetragon process exec in the same pod within one minute | Confirmed Malicious | Capture the audit event and Tetragon event pair verbatim, identify the pod's service account and mounted secrets, then cordon the node before deleting anything |
| `clusterrolebindings` created binding a user to `cluster-admin`, not attributable to a GitOps reconcile | Confirmed Malicious | Record the binding subject and creation timestamp, diff against the GitOps repo head, revoke the binding only after snapshotting the role and its subjects |
| `secrets` listed across many namespaces by one principal | Confirmed Malicious | Determine which secret names were returned from `responseObject`, treat every one as compromised and rotate in dependency order |
| Exec verb matches a documented on-call change ticket from a known operator identity | Benign Baseline | Record ticket ID, keep the principal in the operator baseline rather than excluding the namespace |
| Audit stream holds only `Metadata` stage for the object in question | Inconclusive (Telemetry Gap) | Do NOT close as clean; open a policy change request naming the exact resource and level needed, and use runtime telemetry in the interim |
| Runtime sensor absent on the node hosting the pod | Inconclusive (Telemetry Gap) | Do NOT report "no process ran"; name the uncovered node and request DaemonSet coverage before re-running |

## Containment and Recovery

1. **Preserve before mutating:** Copy the audit JSONL slice and the Tetragon/Falco event stream for the pod, with SHA-256 hashes, before any delete. Pod deletion destroys the container filesystem and the `status.containerStatuses` image ID chain.
2. **Contain at the smallest correct scope:** Apply a deny-all NetworkPolicy to the workload namespace and revoke the specific RoleBinding. Do not cordon the node first unless a hostPath or `hostPID` escalation is confirmed, because cordoning evicts unrelated tenants.
3. **Rotate in dependency order:** Service-account tokens first, then the secrets the pod mounted, then any external credentials those secrets referenced. Kubernetes tokens are long-lived by default; deleting the pod alone does not invalidate them.
4. **Eradicate the entry path:** If the pod spec carried `privileged`, `hostPID` or a hostPath mount, the exposure is admission policy, not the workload. Fix the Pod Security Admission or policy engine rule before restoring the namespace.
5. **Restore with verification:** Recreate from the known-good image digest, confirm the audit stream shows no exec for the recreated pod UID, and confirm the runtime sensor is reporting for the node.
