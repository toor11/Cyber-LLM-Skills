# Detection Signals and Blue-Team Handoff

> Sub-skill: [`xxe`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- XML request bodies containing `<!DOCTYPE` or `<!ENTITY` on endpoints that accept import, upload, or API payloads.
- Outbound connections from the XML-parsing host to an unfamiliar external domain immediately after an XML request.
- File-read audit events for paths such as /etc/passwd or /etc/hostname by the application service account.
- DNS queries from the application subnet for a low-reputation host correlated with an XML POST.
- Parser error events referencing undefined entities, external DTD loading, or entity expansion limits.
- SOAP or SAML message bodies that include a DOCTYPE declaration in the XML envelope.
- Connection attempts from the parsing tier to internal services it has no documented dependency on.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
