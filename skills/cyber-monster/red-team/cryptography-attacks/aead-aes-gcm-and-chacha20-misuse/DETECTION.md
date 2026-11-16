# Detection Signals and Blue-Team Handoff

> Sub-skill: [`aead-aes-gcm-and-chacha20-misuse`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Registry or config field: the `key_version` and `nonce` columns on the ciphertext table — a nonce value reappearing under one `key_version` is the only reliable reuse signal you own.
- Application log field: encrypt-path errors carrying `aead`, `tag mismatch`, or `InvalidTag` — a rising rate across tenants indicates forged or transplanted ciphertext, not key loss.
- Metric: `messages_encrypted_total` labelled by `key_id`; alert when a single `key_id` crosses the `2^32` message budget for a 96-bit random nonce.
- Audit event: KMS `Decrypt` or `GenerateDataKey` calls whose `EncryptionContext` lacks the tenant dimension the encrypt path used.
- Structured field: `aad_len=0` on any encrypt log line, which is the cheapest proxy for the missing-scope branch.
- Database event: a row read whose stored `tenant_id` differs from the `tenant_id` inside the AAD of the blob in that row.
- Network signal: repeated TLS records from one client with identical GCM nonces, visible only on a terminator you control.
- Code-scanning rule: a new call site matching `associated_data=None` in a path that stores ciphertext at rest.

## Handoff

| Target | Purpose |
|---|---|
| [cryptography-design-review](../../../blue-team/application-security/cryptography-design-review/SKILL.md) | Triage queries, alert thresholds, and containment ownership |
