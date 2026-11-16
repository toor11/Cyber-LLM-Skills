# Detection Signals and Blue-Team Handoff

> Sub-skill: [`symmetric-cipher-attacks-weak-key-derivation`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Secret-scanning alert: a high-entropy string in a non-test path, verified against the provider where possible.
- Configuration audit: the same key identifier appearing in manifests for more than one service or environment.
- Key-management event: a KMS key that has never rotated, or a rotation disabled on a key protecting long-lived data.
- Authentication log: decryption failures clustered across tenants, which can indicate one shared key was rotated for a subset.
- Code-scanning rule: a hash function called directly on a passphrase variable and assigned to a key-named variable.
- Deployment diff: an encryption-key environment variable removed or replaced, which changes the derived keys for existing data.
- Runtime signal: a decrypt path that falls back to a legacy key derivation, which is usually selected by a stored flag.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
