# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`saml-and-webauthn-passkey-implementation-flaws`](SKILL.md) | Family: **Web and Application**

Representative diagnostic case structure for this sub-skill:

## Case 1: SAML and Webauthn Passkey Implementation Flaws Assessment & Verification

- **Surface & Preconditions:** Input, identity, or configuration boundary involving `navigator.credentials.get`.
- **Root Cause & Impact:** Missing server-side invariant enforcement or absent telemetry validation across trust boundaries.
- **Verification & Fix:** Confirm with a non-destructive baseline differential and apply the idiomatic control in [`SKILL.md`](SKILL.md).
