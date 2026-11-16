# Detection Signals and Blue-Team Handoff

> Sub-skill: [`password-hashing-and-kdf-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Authentication event: verification duration per user, where legacy rows cluster far below the median — the downgrade population, visible without reading hashes.
- Log field: a `NeedsRehash` or `rehash` marker emitted on successful login, which tracks migration progress as a metric.
- Configuration event: a KDF parameter change in a deploy diff, especially a decrease.
- Database audit: a password column update that changes the hash prefix family for a subset of rows outside a login event.
- Metric: count of rows by stored-format family, reviewed on a schedule, so an old framework default cannot reappear silently.
- Error pattern: verification failures spiking for one format family, which suggests an attacker probing a downgrade path.
- Dependency advisory: a library version whose default cost or default memory was below the current floor.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
