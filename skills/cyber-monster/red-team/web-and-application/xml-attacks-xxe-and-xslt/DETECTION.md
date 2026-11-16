# Detection Signals and Blue-Team Handoff

> Sub-skill: [`xml-attacks-xxe-and-xslt`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application logs where an input field later appears inside an XPath expression string in a query-build log line.
- XSLT engine logs recording document() or extension-function calls during a user-driven transform.
- Parser error events referencing entity expansion limits or maximum entity depth on an XML endpoint.
- Outbound network connections initiated by the XML or XSLT processor to a non-whitelisted host.
- Requests whose body contains `system-property(`, `xi:include`, or `<xsl:` on an endpoint that expects data XML.
- A latency spike on an XML-processing route correlated with request bodies containing nested entity declarations.
- Schema or DTD fetch requests from the application to an external URL recorded in egress logs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
