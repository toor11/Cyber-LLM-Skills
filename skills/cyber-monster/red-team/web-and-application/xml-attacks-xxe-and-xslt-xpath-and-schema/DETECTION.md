# Detection Signals and Blue-Team Handoff

> Sub-skill: [`xml-attacks-xxe-and-xslt-xpath-and-schema`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application query-build logs where a username or search term appears inside an XPath predicate string.
- Authentication attempts whose input field contains `or '1'='1`, `or 1=1`, or an unbalanced single quote.
- Parser error events citing entity expansion depth or memory limits on an XML validation route.
- A parse-time or CPU spike on an XML endpoint correlated with request bodies declaring nested entities.
- Requests containing `xi:include` or an XInclude namespace on an endpoint expecting plain data XML.
- Egress fetches for a schema or DTD URL recorded when a document is validated.
- Repeated near-identical search requests differing only by a trailing quote or boolean clause from one session.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
