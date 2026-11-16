# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`aead-aes-gcm-and-chacha20-misuse`](SKILL.md) | Family: **Cryptography Attacks**

Representative diagnostic case structure for this sub-skill:

## Case 1: AEAD Aes GCM and Chacha20 Misuse Assessment & Verification

- **Surface & Preconditions:** Input, identity, or configuration boundary involving `AES-GCM 96-bit nonce`.
- **Root Cause & Impact:** Missing server-side invariant enforcement or absent telemetry validation across trust boundaries.
- **Verification & Fix:** Confirm with a non-destructive baseline differential and apply the idiomatic control in [`SKILL.md`](SKILL.md).
