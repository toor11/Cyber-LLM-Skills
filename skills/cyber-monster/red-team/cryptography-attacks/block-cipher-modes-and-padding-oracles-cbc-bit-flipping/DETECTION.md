# Detection Signals and Blue-Team Handoff

> Sub-skill: [`block-cipher-modes-and-padding-oracles-cbc-bit-flipping`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Request field: presence of `iv`, `nonce`, or `salt` in a decrypt or session-load request body, which is the client-controlled-IV fingerprint.
- Response field: a session or token whose decoded field value differs from the value the same session had on issue, tracked by session id.
- Error pattern: a burst of parse or decode errors on the session-load route from one client, which is the bit sweep walking block boundaries.
- Application log: `BadPaddingException` or `UnpadError` on a route that also accepts an `iv` parameter.
- Configuration event: a provider string change from `AES/CBC/PKCS5Padding` to `AES/GCM/NoPadding` in a deploy diff — the remediation signal.
- Database audit: a session row whose ciphertext changed without a corresponding write event from the application.
- Header signal: a cookie whose base64 payload length is an exact multiple of 16 and whose first 16 bytes vary while the rest is stable.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
