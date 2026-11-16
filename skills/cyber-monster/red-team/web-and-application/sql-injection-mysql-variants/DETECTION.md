# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sql-injection-mysql-variants`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- MySQL error 1105 or 1064 carrying an XPATH fragment from updatexml or extractvalue with request-derived text.
- Query latency on one route increasing in steps matching a SLEEP argument.
- References to information_schema.tables or information_schema.columns in queries whose plan never needs them.
- Versioned slash-bang comment sequences appearing in inbound request parameters.
- LOAD_FILE or INTO OUTFILE tokens in the MySQL general query log correlated with web input.
- @@version or @@datadir calls in the query text of parameterised endpoints.
- WAF injection-rule hits for SLEEP or extractvalue followed by a 200 from the MySQL-backed origin.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | Detection queries, triage, and hardening for this technique |
