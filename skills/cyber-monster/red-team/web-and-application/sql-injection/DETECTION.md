# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sql-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- HTTP request logs where a single parameter alternates between two structurally different SQL literals from the same session within seconds.
- Database error events (PostgreSQL `SQLSTATE 42601`, MySQL error 1064, SQL Server 102) whose statement text contains a quote or comment marker originating from request input.
- WAF or gateway `sqli` rule hits followed by a 200 from the origin on the same route, which indicates the payload passed the filter.
- Query latency distribution shifts on one route while request volume stays flat, characteristic of a bounded delay probe.
- New outbound DNS or HTTP connections from the application host to an unfamiliar domain shortly after a request to a data-driven route.
- `information_schema`, `pg_catalog`, or `sysobjects` appearing in application logs where the normal query plan never references them.
- Audit entries for raw-fragment ORM calls (`whereRaw`, `extra`) correlated with request parameters that contain quote characters.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | Detection queries, triage, and hardening for this technique |
