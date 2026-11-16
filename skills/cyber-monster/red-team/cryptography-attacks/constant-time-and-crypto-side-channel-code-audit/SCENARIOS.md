# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`constant-time-and-crypto-side-channel-code-audit`](SKILL.md) | Family: **Cryptography Attacks**

Representative diagnostic case structure for this sub-skill:

## Case 1: Constant Time and Crypto Side Channel Code Audit Assessment & Verification

- **Surface & Preconditions:** Input, identity, or configuration boundary involving `hmac.compare_digest`.
- **Root Cause & Impact:** Missing server-side invariant enforcement or absent telemetry validation across trust boundaries.
- **Verification & Fix:** Confirm with a non-destructive baseline differential and apply the idiomatic control in [`SKILL.md`](SKILL.md).
