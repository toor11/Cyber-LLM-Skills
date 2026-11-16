# Detection Signals and Blue-Team Handoff

> Sub-skill: [`path-traversal-and-lfi-encoding-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs containing %2f, %252f, %5c, %c0%ae, or %00 sequences in a file or path parameter.
- Requests where a reverse proxy forwards a still-encoded path that the origin then decodes a second time.
- A single session cycling through single, double, and overlong encodings of the same traversal.
- Web process file opens outside the content root following a request with encoded path bytes.
- WAF decode events whose normalised path differs from the path the origin ultimately resolves.
- Responses returning system file contents on a route whose parameter carried percent-encoded dot sequences.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) | Detection queries, triage, and hardening for this technique |
