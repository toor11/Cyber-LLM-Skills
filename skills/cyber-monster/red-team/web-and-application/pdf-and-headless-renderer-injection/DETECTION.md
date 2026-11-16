# Detection Signals and Blue-Team Handoff

> Sub-skill: [`pdf-and-headless-renderer-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Outbound requests whose User-Agent is wkhtmltopdf, HeadlessChrome, or WeasyPrint arriving at external or internal hosts.
- Connections from the PDF or screenshot worker to 169.254.169.254 or RFC1918 ranges.
- PDF generation jobs whose input HTML contains file://, at-import, iframe, or rel="attachment".
- DNS lookups from the renderer microservice to low-reputation or newly seen hosts.
- Render latency outliers on jobs that reference internal hostnames or ports.
- Egress from the renderer service to administrative ports such as 6379, 9200, or 2375 with no documented dependency.
- Renderer error logs surfacing internal hostnames or file paths from a failed resource fetch.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
