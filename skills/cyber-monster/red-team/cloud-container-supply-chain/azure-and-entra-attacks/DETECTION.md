# Detection Signals and Blue-Team Handoff

> Sub-skill: [`azure-and-entra-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Entra audit log: `Consent to application` with `ConsentContext.IsAdminConsent` true and a scope list containing mail or directory scopes.
- Entra sign-in log field: `authenticationRequirement` and `tokenProtectionStatus` on a session, which shows whether Token Protection applied.
- Entra audit event: `Add delegated permission grant` for `AllPrincipals`, reviewed on every occurrence.
- Sign-in log: a successful sign-in whose `continuousAccessEvaluationStatus` is `notApplied` on a resource in the sensitive tier.
- Risk detection: `anonymizedIPAddress` or `unfamiliarFeatures` followed by a successful token use, which indicates replay.
- Configuration event: an `oauth2PermissionGrant` created outside a change window.
- Access review result: a guest or service principal retaining a grant across two review cycles.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
