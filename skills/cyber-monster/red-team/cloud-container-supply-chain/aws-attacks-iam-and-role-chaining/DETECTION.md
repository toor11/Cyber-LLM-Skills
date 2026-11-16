# Detection Signals and Blue-Team Handoff

> Sub-skill: [`aws-attacks-iam-and-role-chaining`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- CloudTrail event: `iam:CreatePolicyVersion` with `setAsDefault: true`, which is the mutation hop in one record.
- CloudTrail event: `iam:UpdateAssumeRolePolicy`, which changes who can enter a role and should never happen outside a change window.
- CloudTrail field: `sts:AssumeRole` where the `externalId` is missing on a role whose trust requires one.
- Access Analyzer finding: a role whose trust policy admits a principal outside the account without a condition.
- CloudTrail correlation: `iam:PassRole` followed within seconds by `lambda:CreateFunction` or `ec2:RunInstances` from the same principal.
- GuardDuty finding: `PrivilegeEscalation:IAMUser/AdministrativePermissions` or the role-chaining variants.
- IAM credential report: a role with `sts:AssumeRole` activity from a principal ARN that is not in the approved chain list.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
