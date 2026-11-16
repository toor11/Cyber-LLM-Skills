# Detection Signals and Blue-Team Handoff

> Sub-skill: [`block-cipher-modes-and-padding-oracles`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Web access-log field: request path plus response status for the decrypt endpoint grouped by request body length — a status that splits on padding validity shows up as two clusters.
- Application log field: exception class name (`BadPaddingException`, `ValueError` from `unpadder`) counted per handler, which is the cheapest oracle inventory you can build.
- Response metric: `http_response_size_bytes` distribution on the decrypt route; a body length that varies with padding validity is an oracle even when the status matches.
- Timing metric: p99 latency on the decrypt route split by request validity, using a high-percentile comparison rather than the mean.
- Data-at-rest signal: ciphertext column lengths that are always a multiple of 16 while the plaintext lengths vary, which is the fingerprint of block padding without a MAC.
- Configuration event: a `Cipher.getInstance` mode change to `ECB` or `CBC` in a deploy diff, caught from the build artefact rather than runtime.
- Database audit record: an update to a blob column whose value is not byte-identical to the previous value but decrypts to the same plaintext, which is the signature of a malleability probe.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
