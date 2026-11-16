# Detection Signals and Blue-Team Handoff

> Sub-skill: [`crypto-implementation-review`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Repository event: a commit adding a literal matching a high-entropy pattern in a non-test path, caught by pre-receive scanning.
- Configuration field: an encryption mode or KDF parameter value in a config diff that lowers a work factor or removes an IV source.
- Dependency signal: a new direct dependency in the crypto path, which is where home-made constructions usually enter.
- Runtime field: a decrypt or verify call site that appears in a stack trace without a corresponding library MAC frame.
- Secret-scanning alert: a verified provider credential in a commit, which turns a custody note into an incident.
- Audit record: key version rotated in KMS while application config still names the previous version.
- Code-owner signal: a change to a crypto module without a review from the team that owns the threat model.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
