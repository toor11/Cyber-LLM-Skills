# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssti-jinja2-and-twig`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- WAF or application logs where a single query parameter contains `{{`, `}}`, `{%`, or `%}` sequences reaching a server-rendered route.
- Flask or Symfony error events naming `jinja2.exceptions` or `Twig\Error\SyntaxError` with a template string that includes request bytes.
- Application logs showing `render_template_string` or Twig `createTemplate` calls whose argument length tracks an inbound parameter.
- Response bodies on a templated endpoint containing serialized `config` keys such as `SECRET_KEY` that the view never intentionally emits.
- Process telemetry where the web worker (`python`, `php-fpm`) spawns a shell child shortly after a request carrying template delimiters.
- Spikes in 500 responses on one templated route correlated with inbound `{{ }}` payloads, indicating parse attempts.
- File-read or egress audit entries from the rendering worker that reference engine internals like `__globals__` or `_self`.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
