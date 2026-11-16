# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cloud-persistence-and-defense-evasion`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- CloudTrail event: `iam:CreateAccessKey` for a user other than the caller, which is the credential-persistence shape.
- CloudTrail event: `iam:UpdateAssumeRolePolicy` or a new federated credential, which is grant persistence.
- CloudTrail event: `cloudtrail:StopLogging`, `DeleteTrail`, or `UpdateTrail`, which should never occur outside a change window.
- Entra audit event: `Add service principal credentials` or `Certificates and secrets management` on an app the actor does not own.
- GuardDuty finding: `Persistence:IAMUser/UserPermissions` or the role-name variants.
- EventBridge and Lambda inventory: a scheduled rule whose target function is absent from the IaC state.
- Configuration drift: a GuardDuty detector disabled or a Security Hub standard turned off.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
