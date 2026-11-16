# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssti-java-template-engines`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Freemarker TemplateException or parse errors in logs referencing request-derived template text.
- SpEL EvaluationException entries from Thymeleaf or Spring correlated with request parameters.
- Code scans finding new Template(...) or SpelExpressionParser fed request input.
- Rendered responses where a dollar-brace or #set expression from input returns a computed value.
- Template model objects reaching #ctx, T(java.lang.Runtime), or TemplateClassResolver in logs.
- JVM process-spawn or ProcessBuilder events on the rendering tier following template-like input.
- Thymeleaf TemplateManager invocations triggered recursively within a single render.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
