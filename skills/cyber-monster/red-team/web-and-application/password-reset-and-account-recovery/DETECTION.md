# Detection Signals and Blue-Team Handoff

> Sub-skill: [`password-reset-and-account-recovery`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Reset emails or logs where the link host differs from the canonical application domain.
- Inbound forgot-password requests carrying a Host or X-Forwarded-Host that does not match the configured host.
- The same reset token submitted more than once to the acceptance endpoint.
- A spike of forgot-password requests enumerating many distinct email addresses from one source.
- Recovery-code verification endpoints receiving many attempts per account within a short window.
- Reset tokens in logs that are short, sequential, or share a common timestamp-derived prefix.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
