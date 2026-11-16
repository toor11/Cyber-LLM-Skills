# Detection Signals and Blue-Team Handoff

> Sub-skill: [`code-injection-and-eval-expression-language`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Spring application logs recording `org.springframework.expression.spel.SpelEvaluationException` with a fragment traceable to request input.
- Struts or OGNL logs showing `ognl.OgnlException` or value-stack evaluation of a parameter containing `%{` or `@java`.
- Request access logs where a parameter carries `${`, `#{`, `%{`, or `T(` sequences on a route that renders names or templates.
- JVM telemetry showing `java.lang.Runtime.exec` or `ProcessBuilder` invocation on a thread that handled an expression-rendering request.
- WAF hits on SpEL or OGNL signatures followed by a 200 from the origin on the same endpoint.
- Reflection calls (`Class.forName`, `getDeclaredMethod`) appearing in profiler traces tied to a template or rule evaluation path.
- A greeting, rule, or label endpoint returning computed arithmetic where the baseline is always static text.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
