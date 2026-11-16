# Detection Signals and Blue-Team Handoff

> Sub-skill: [`file-upload-and-webshell`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web server logs where a POST to an upload route is followed by a GET under the upload directory returning a dynamic content type.
- Upload directories gaining files with scripting extensions (`.php`, `.phtml`, `.jsp`, `.aspx`) where only media was expected.
- Access logs showing the stored upload URL requested by an external source within seconds of the upload.
- File-integrity events creating executable-handler files in a directory configured for user uploads.
- Responses from the upload directory carrying `Content-Type: text/html` or script output rather than the stored image MIME.
- WAF multipart-inspection hits on magic-byte or extension mismatches in upload bodies.
- Archive-extraction jobs writing member paths that resolve under the web root.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response-webshell-discovery`](../../../blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md) | Detection queries, triage, and hardening for this technique |
