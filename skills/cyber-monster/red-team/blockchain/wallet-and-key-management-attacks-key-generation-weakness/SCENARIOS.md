# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`wallet-and-key-management-attacks-key-generation-weakness`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Timestamp-Seeded Test Wallet in Production

- **Surface & Preconditions:** A deployment script creates a wallet with a seed derived from the current time.
- **Root Cause & Impact:** The key space is small enough to enumerate for anyone who knows the deployment date.
- **Verification & Fix:** Replace the seed with CSPRNG bytes, rotate the key and every approval it granted, and record the disclosure.

## Case 2: Repeated Nonce Across Two Signatures

- **Surface & Preconditions:** A custom signing implementation uses a counter for `k`.
- **Root Cause & Impact:** Two signatures over distinct messages reveal the private key, and the address must be treated as compromised.
- **Verification & Fix:** Move to deterministic RFC 6979 signing, rotate the key, and add a test that asserts differing `r` values.
