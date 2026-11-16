# Detection Signals and Blue-Team Handoff

> Sub-skill: [`server-side-includes-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Request parameters or stored fields containing the comment-and-hash directive opener reaching an SSI-enabled route.
- Apache error_log entries referencing mod_include with 'unknown directive' or 'exec used but not allowed'.
- Access logs for .shtml, .shtm, or .stm paths carrying user-influenced query or body content.
- Responses from an SSI route whose length changes when the same field alternates between encoded and raw comment syntax.
- Configuration changes adding Options with Includes or an INCLUDES output filter to a user-facing directory.
- Child processes spawned by the web server account immediately after a request to an SSI page.
- Outbound connections or file reads initiated while rendering a .shtml page that normally serves static content.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
