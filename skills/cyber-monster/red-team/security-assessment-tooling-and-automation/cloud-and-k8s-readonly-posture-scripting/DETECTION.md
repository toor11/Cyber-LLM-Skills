# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cloud-and-k8s-readonly-posture-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- CloudTrail `List*` and `Get*` events from one principal across many services in a short window.
- `AccessDenied` bursts for a single principal, the signature of a collector probing permissions it does not hold.
- Kubernetes audit events with verb `list` against `clusterrolebindings` or `pods` across all namespaces.
- `system:anonymous` or a default service account issuing list calls, which is itself a posture finding.
- STS `AssumeRole` into a read-only role from an IP outside the assessment range.
- GuardDuty or CloudTrail findings tagged `Discovery:` for the credential pattern used by the collector.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
