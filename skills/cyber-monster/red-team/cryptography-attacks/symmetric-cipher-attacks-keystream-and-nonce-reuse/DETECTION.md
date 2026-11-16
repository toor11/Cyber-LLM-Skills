# Detection Signals and Blue-Team Handoff

> Sub-skill: [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Storage field: unique-index or group-by on the nonce column, alerted when a duplicate appears under one key.
- Application metric: ciphertext-prefix collisions per key per hour, which is the online reuse detector.
- Data signal: two ciphertexts whose XOR yields printable runs, detectable by a periodic scan over a sample.
- Code-scanning rule: a literal nonce or a zero nonce in a stream-cipher call.
- Process event: a restart correlated with a nonce counter reset, which is the reset window.
- Cryptographic metric: messages encrypted per nonce start value, compared with the counter width.
- Audit record: a key used with a random 64-bit counter start at a message volume approaching the overlap bound.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
