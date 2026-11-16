# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`compromised-credentials-and-token-revocation-playbook`](SKILL.md) | Family: **Incident Response**

Representative diagnostic case structure for this sub-skill:

## Case 1: Compromised Credentials and Token Revocation Playbook Assessment & Verification

- **Surface & Preconditions:** Input, identity, or configuration boundary involving `revokeSignInSessions`.
- **Root Cause & Impact:** Missing server-side invariant enforcement or absent telemetry validation across trust boundaries.
- **Verification & Fix:** Confirm with a non-destructive baseline differential and apply the idiomatic control in [`SKILL.md`](SKILL.md).
