# Detection Signals and Blue-Team Handoff

> Sub-skill: [`aws-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- CloudTrail event: `iam:PassRole` with a `requestParameters.roleARN` that the calling principal has never passed before.
- CloudTrail event: `iam:CreatePolicyVersion` or `iam:AttachRolePolicy` outside a change window, which is the policy-mutation hop.
- CloudTrail field: `sts:AssumeRole` where `requestParameters.externalId` is absent on a role whose trust policy requires one.
- Access Analyzer finding: a resource policy granting access to a principal outside the zone of trust.
- CloudTrail event: `sts:AssumeRoleWithWebIdentity` from a token issuer not in the approved set.
- IAM Access Analyzer unused-access field: a role with no `sts:AssumeRole` in 90 days that still holds broad permissions.
- Configuration event: a permission boundary removed from a principal that retains its policies.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
