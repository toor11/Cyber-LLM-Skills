# Detection Signals and Blue-Team Handoff

> Sub-skill: [`symmetric-cipher-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Encryption-service metric: ciphertext prefix collisions per key over a rolling window, which is the direct reuse detector.
- Process event: a restart of the encryption service correlated with a burst of new messages, which is the reset window.
- Configuration field: one key identifier used by more than one tenant or service, which is the blast-radius signal.
- Code-scanning rule: a counter object constructed inside a request handler rather than loaded from durable state.
- Data signal: two stored ciphertexts for rows with identical plaintext that are byte-identical in their first block.
- Cryptographic metric: bytes encrypted per key, compared against the nonce space for the observed width.
- Audit record: a key version that never increments across a quarter, which is the unrotated-key signal.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
