# Detection Signals and Blue-Team Handoff

> Sub-skill: [`azure-and-entra-attacks-token-and-consent-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Entra audit event: `Consent to application` where `targetResources.modifiedProperties` contains `offline_access` and a data scope.
- Entra audit event: `Add delegated permission grant` with `consentType: AllPrincipals`.
- Service principal field: `verifiedPublisher.displayName` empty on a principal that holds a data grant — the unverified-external signal.
- Sign-in log: `tokenIssuerType` refresh-token redemption from an ASN the user has never used.
- Sign-in log: a successful sign-in to an application whose `appOwnerOrganizationId` differs from the tenant.
- Conditional Access report-only hit: a policy that would have blocked the consenting client, showing the control was not enforced.
- Configuration event: an authorisation policy change that widened `permissionGrantPoliciesAssigned`.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
