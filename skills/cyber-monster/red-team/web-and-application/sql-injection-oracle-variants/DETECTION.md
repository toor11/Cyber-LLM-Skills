# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sql-injection-oracle-variants`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- ORA-prefixed errors such as ORA-01756, ORA-00933, or ORA-29257 in application logs carrying request-derived values.
- Query latency on one route increasing in steps matching a DBMS_PIPE.RECEIVE_MESSAGE timeout.
- Outbound DNS or HTTP from the database host to an unfamiliar domain following a request, indicating UTL_INADDR or UTL_HTTP.
- References to ALL_TABLES, ALL_TAB_COLUMNS, or v$version in queries whose plan never needs them.
- UNION SELECT constructions ending in FROM DUAL in Oracle audit-trail statements tied to web input.
- Execution of UTL_HTTP, UTL_INADDR, or DBMS_LDAP by the application schema in Oracle fine-grained audit.
- WAF injection-rule hits for DBMS_PIPE or UTL_HTTP followed by a 200 from the Oracle-backed origin.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | Detection queries, triage, and hardening for this technique |
