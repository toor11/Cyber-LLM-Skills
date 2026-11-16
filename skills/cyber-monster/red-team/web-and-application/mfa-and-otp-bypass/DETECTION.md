# Detection Signals and Blue-Team Handoff

> Sub-skill: [`mfa-and-otp-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Authentication logs with many consecutive failed second-factor events (mfa_failed) for one account or pending-session id within seconds and no lockout event.
- The same OTP or TOTP value appearing in two mfa_verify success events for one user (reuse).
- An mfa_verify success not preceded by a password_ok event for the same session, indicating a skipped step.
- Factor codes submitted with whitespace or leading-zero variants, seen as a varying code-field length.
- A code issued for one account_id presented against a different account_id in the verification request body.
- Backup-code redemption events at a rate far above baseline or without a preceding primary-factor failure.
- WebAuthn assertion events where the credential type (discoverable versus non-discoverable) differs from the registration policy.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
