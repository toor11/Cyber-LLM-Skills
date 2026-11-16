# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssti-node-and-client-engines`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Reverse-proxy logs where a parameter carries `<%=`, `<%-`, `#{`, or `{{{` sequences into a Node-rendered route.
- Node process logs showing `ejs`, `pug`, or `handlebars` compile errors referencing request-derived template text.
- Browser CSP violation reports via `report-uri` or `report-to` on framework pages, indicating a client-side expression attempted script execution.
- Front-end error telemetry where an Angular `$parse` or a Vue render function throws on an unexpected expression containing request data.
- APM spans where `res.render` latency or template-compile count rises in lockstep with a single query parameter.
- Node worker spawning `child_process` shortly after a request containing `constructor.constructor` tokens.
- WAF events tagging template delimiters on routes whose responses are served as `text/html` from a Node upstream.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
