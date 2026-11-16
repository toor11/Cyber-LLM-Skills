# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cloud-iam-privilege-escalation`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- CloudTrail event: a policy-mutation or role-assignment API called by a principal whose normal behaviour is read-only.
- Azure Activity log: `Microsoft.Authorization/roleAssignments/write` for the caller's own object id, which is the self-grant shape.
- GCP Audit Log: `SetIamPolicy` on a service account adding a member outside the approved group.
- CloudTrail correlation: an assumption followed within seconds by a permission-changing call.
- GuardDuty finding: `PrivilegeEscalation:IAMUser/AdministrativePermissions`.
- IAM Access Analyzer: a policy that grants an escalation primitive on a wildcard resource.
- Configuration event: a new trust edge to an external account or a wildcard principal.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
