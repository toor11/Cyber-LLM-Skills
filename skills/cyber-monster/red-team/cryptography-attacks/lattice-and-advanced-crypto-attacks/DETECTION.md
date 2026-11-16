# Detection Signals and Blue-Team Handoff

> Sub-skill: [`lattice-and-advanced-crypto-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Application log field: any response body containing a hex string whose length is a fraction of the key size and whose source is the private key object.
- Access-log pattern: repeated calls to a key-diagnostics or debug endpoint from a principal that never uses it in normal operation.
- Key-generation audit: a run whose timing distribution is narrower than expected, which is the fingerprint of a weak RNG producing structured primes.
- Signature corpus metric: bit-length distribution of `r` values per key, which is the nonce-bias measurement done continuously.
- Certificate field: two certificates in the same estate whose moduli share a non-trivial GCD.
- Dependency signal: an HSM firmware version named in a partial-key-exposure advisory.
- Configuration event: a modulus size reduction in a key-generation profile.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
