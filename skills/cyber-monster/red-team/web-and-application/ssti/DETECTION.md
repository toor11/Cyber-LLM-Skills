# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssti`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application responses where a request parameter containing 7*7 is returned as 49.
- Template engine stack traces such as Jinja2 UndefinedError or Freemarker TemplateException referencing request input.
- Calls to render_template_string or equivalent string-render APIs with request-derived arguments in code scans.
- Template context objects reached from request fields such as __class__, __mro__, or config in logs.
- Spikes in template compilation events tied to unique per-request template sources.
- WAF hits for {{ }} or ${ } sequences on routes that render user content.
- CPU or process-spawn anomalies on the rendering tier following template-like input.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
