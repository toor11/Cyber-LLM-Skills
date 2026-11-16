# Detection Signals and Blue-Team Handoff

> Sub-skill: [`saas-oauth-app-and-m365-workspace-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Entra audit event: `Consent to application` with `offline_access` and a data scope in `modifiedProperties`.
- Entra sign-in log: an authorize request without a PKCE challenge, visible only if the client is instrumented.
- Exchange audit event: `New-InboxRule` with a `ForwardTo` or `RedirectTo` address outside accepted domains.
- Exchange audit event: `Add-MailboxPermission` granting `FullAccess` to a non-admin principal.
- Graph audit: an application token used for a mailbox the application never served before.
- Configuration event: a redirect URI added to an app registration, especially one with a wildcard or a non-HTTPS scheme.
- Transport rule audit: a forwarding-block rule disabled or modified.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
