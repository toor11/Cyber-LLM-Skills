# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ldap-and-xpath-injection-xpath`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application logs where a `name` or `id` parameter feeding an XML lookup contains `'`, `or`, `count(`, or `substring(` tokens.
- XML processing errors (XPathException, SAXParseException, lxml XPathEvalError) correlated with one session.
- A user-lookup route returning a node count far above its historical median after a predicate-shaped parameter.
- Successful authentication events where the username field contains a quote or boolean keyword.
- Repeated requests walking a substring index (,1,1)='a', (,2,1)='b'), characteristic of blind extraction.
- WAF signatures for XPath functions (`count(`, `string-length(`) followed by a 200 from the origin.
- Use of `doc()` or `document()` with an external URL in query logs from an XPath 2.0 processor.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
