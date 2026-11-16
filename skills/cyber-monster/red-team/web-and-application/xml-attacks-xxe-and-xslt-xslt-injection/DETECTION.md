# Detection Signals and Blue-Team Handoff

> Sub-skill: [`xml-attacks-xxe-and-xslt-xslt-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Requests whose body contains `<xsl:`, `system-property(`, or `document(` on an endpoint that expects a data document.
- XSLT engine logs recording a document() call or an extension-function invocation during a user transform.
- Outbound fetches initiated by the transform process to an external or internal URL named in a stylesheet.
- Error events naming the XSLT processor when a capability or extension call is attempted.
- A stored stylesheet field in the database whose value contains an extension namespace declaration.
- Transform results served as HTML that contain unescaped script markup originating from the result tree.
- File-read audit events for paths referenced by document() during a transform job.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
