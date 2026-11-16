# Detection Signals and Blue-Team Handoff

> Sub-skill: [`prng-and-nonce-attacks-signature-nonce-reuse`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Signature corpus metric: duplicate `r` values per public key across all issued signatures, which is the direct detector and needs no side channel.
- Signing-service log: a signing call whose nonce source is an application-supplied value rather than the library's derivation.
- Cryptographic metric: bit-length distribution of `r` per key, tracked to detect a biased RNG before a lattice is feasible.
- HSM audit: a firmware version named in a nonce-bias advisory for the same device family.
- Certificate transparency signal: two certificates from one key whose signatures share `r`, visible in public logs.
- Dependency event: a signing library upgrade that changes the default nonce derivation.
- Error metric: signature verification failures clustered after a key rotation, which can indicate a mismatched derivation.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
