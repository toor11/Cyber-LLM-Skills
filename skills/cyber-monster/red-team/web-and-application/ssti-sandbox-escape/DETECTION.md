# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssti-sandbox-escape`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Template engine logs emitting `SecurityError` or `jinja2.exceptions.SecurityError` bursts from one route, indicating sandbox probing.
- Dependency manifests such as `requirements.txt` or `composer.lock` pinning Jinja2, Twig, or Xibo versions below the advisory fix.
- Request bodies containing `|attr(`, `__globals__`, `_self`, or `#ctx` reaching a template-rendering endpoint.
- Rendering worker process opening `/bin/sh`, sockets, or files during a request that carried template gadget tokens.
- EDR parent-child telemetry where `python`, `php-fpm`, or `java` spawns a shell immediately after template evaluation.
- Repeated 200 responses to expressions differing only by `.attr` versus `|attr`, the signature of mediation testing.
- Container runtime alerts for unexpected egress from a template-render sidecar that should have no network.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
