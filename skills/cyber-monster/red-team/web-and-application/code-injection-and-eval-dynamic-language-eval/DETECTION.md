# Detection Signals and Blue-Team Handoff

> Sub-skill: [`code-injection-and-eval-dynamic-language-eval`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Python `sys.audit` events for `exec` or `compile` emitted on a request-handling thread that normally only reads data.
- Ruby or Node runtime logs recording `instance_eval` or Function-constructor compilation with an argument traceable to a JSON body field.
- Application error logs where a filter or rule parameter produces `NameError`, `NoMethodError`, or `ReferenceError` referencing attacker tokens.
- A filter or search endpoint whose response size alternates between two stable values in lock-step with a boolean-looking parameter.
- Interpreter worker spawning subprocesses or opening files immediately after a request to a rule-evaluation route.
- Introspection tokens such as `__subclasses__`, `__globals__`, or `constructor.constructor` appearing in request bodies in the access log.
- Spikes in garbage-collection or compile counters on a service whose eval path is supposed to be data-only.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
