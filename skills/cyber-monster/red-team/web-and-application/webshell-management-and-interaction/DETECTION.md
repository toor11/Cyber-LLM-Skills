# Detection Signals and Blue-Team Handoff

> Sub-skill: [`webshell-management-and-interaction`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web access-log POSTs that write to an upload directory followed by GETs to the same path with an executable extension.
- FPM or servlet-container logs showing a script executed from a path under the uploads directory.
- Request bodies or parameters containing base64 blobs on a single endpoint, characteristic of antsword or behinder encoders.
- User-Agent strings matching weevely, antsword, Godzilla, or behinder in the request log.
- New files with .php, .jsp, .aspx, or .phar extensions appearing in a directory that should hold only user media.
- Outbound connections initiated by the web-server process to an external host shortly after a request to an upload path.
- File-integrity monitoring events for creation of executable-mapped files inside the document root.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
