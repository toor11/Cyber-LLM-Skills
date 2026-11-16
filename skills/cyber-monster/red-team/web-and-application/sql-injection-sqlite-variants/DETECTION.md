# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sql-injection-sqlite-variants`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application logs containing SQLite messages such as `unrecognized token`, `no such column`, or `near "...": syntax error` tied to request parameters.
- References to `sqlite_master` in queries that the normal application flow never issues.
- Response-time spikes on one route correlating with `randomblob` or other heavy expressions in the query text.
- `ATTACH DATABASE` or `load_extension` statements appearing in query logs from request handlers.
- `JSON_EXTRACT` calls with malformed path arguments sourced from input.
- Repeated `ORDER BY` ordinal increments from a single session against one endpoint.
- SQLite file modification timestamps changing outside deploy or migration windows.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | Detection queries, triage, and hardening for this technique |
