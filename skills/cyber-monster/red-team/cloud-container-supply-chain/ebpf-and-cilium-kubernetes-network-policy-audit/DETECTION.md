# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ebpf-and-cilium-kubernetes-network-policy-audit`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Hubble flow log: a `DROPPED` verdict for a flow the policy should deny, which is the enforcement evidence, and an `ALLOWED` verdict for one it should deny is the finding.
- Kubernetes audit log: a `NetworkPolicy` deleted or its `policyTypes` reduced.
- Cilium agent log: a policy computation error or a datapath reload, which can leave a window where no policy applies.
- CNI version field: an agent image tag inside an advisory range, checked on every upgrade.
- Egress metric: bytes leaving a namespace to destinations outside the declared egress rules.
- Admission audit: a pod created with a label that matches a broad policy selector rather than a specific one.
- Configuration event: `bpf.hostRouting` or `endpointRoutes.enabled` changed in a Helm values diff.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
