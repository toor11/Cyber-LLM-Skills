# Detection Signals and Blue-Team Handoff

> Sub-skill: [`gcp-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Cloud Audit Log: `SetIamPolicy` on a project or service account with a `serviceAccount:` member added by a human principal.
- Cloud Audit Log: `google.iam.admin.v1.CreateServiceAccountKey`, which is the key-minting event and should be zero under the constraint.
- Cloud Audit Log: `GenerateAccessToken` or `GenerateIdToken` on a service account, which is the `actAs` in use — high volume from one principal indicates impersonation.
- Org Policy audit: a constraint override created with an exception tag, which reopens the path the constraint closed.
- Workload Identity Federation: a token exchange from an issuer or attribute set outside the provider's condition.
- Asset Inventory: a new `roles/editor` or `roles/owner` binding at folder or organisation scope.
- VPC Service Controls: an access denied event on a perimeter boundary, which shows an unexpected cross-perimeter call.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
