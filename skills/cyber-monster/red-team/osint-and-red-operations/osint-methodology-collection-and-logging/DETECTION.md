# Detection Signals and Blue-Team Handoff

> Sub-skill: [`osint-methodology-collection-and-logging`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Access logs showing sequential queries across unrelated OSINT providers from one internal host.
- Registry or CT API rate-limit responses attributed to a single API key.
- SQLite WAL files (`-wal`, `-shm`) in a working directory, indicating an active collection store.
- Retrieval of the same record from the same client at fixed intervals.
- Bulk archive (CDX) queries for a single domain from one address.
- Exported CSV of an observation table appearing in a shared drive outside the engagement workspace.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
