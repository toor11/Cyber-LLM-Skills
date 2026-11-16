# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ldap-and-xpath-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Directory-server logs showing search filters with unbalanced parentheses or *)(uid= sequences from the application bind account.
- Application logs where a login or search parameter contains )(|, *)( , or ' or '1'='1 before reaching the directory.
- LDAP result sizes spiking to the entire subtree for a single search request.
- XML or XPath engine errors referencing malformed expressions during a search feature.
- Repeated authentication successes for the same account consistent with boolean-differential probing.
- WAF events tagging LDAP or XPath metacharacters on parameters that feed directory queries.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
