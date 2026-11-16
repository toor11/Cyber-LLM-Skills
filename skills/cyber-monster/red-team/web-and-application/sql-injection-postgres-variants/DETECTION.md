# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sql-injection-postgres-variants`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Postgres server logs with ERROR 42601 or 42703 whose statement text contains a quote sourced from an HTTP parameter.
- `invalid input syntax for type integer` messages in application logs tied to a user-supplied id or filter.
- Query latency on one route tracking a `pg_sleep` argument while request volume stays flat.
- `pg_stat_statements` entries showing structurally different queries for the same endpoint within a session.
- References to `pg_catalog`, `pg_tables`, or `current_setting` in queries from a role that normally touches only application tables.
- `COPY ... TO PROGRAM` or large-object calls originating from the web application role.
- WAF rule hits for single quotes on a route followed by a 200 from the Postgres-backed origin.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | Detection queries, triage, and hardening for this technique |
