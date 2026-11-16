# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sql-injection-mssql-variants`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- SQL Server error 245 or 8114 (conversion failed) in application logs with request-derived values in the message.
- Query latency on one route increasing in five-second steps matching a WAITFOR DELAY interval.
- T-SQL batches containing a semicolon followed by a second statement originating from request input.
- References to sys.databases, sys.objects, or INFORMATION_SCHEMA in queries whose plan never uses them.
- xp_cmdshell or sp_OACreate invocations in SQL Server traces correlated with web request parameters.
- @@version or SERVERPROPERTY calls appearing in the query text of parameterised endpoints.
- WAF injection-rule hits for WAITFOR or CONVERT followed by a 200 from the SQL Server-backed origin.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | Detection queries, triage, and hardening for this technique |
