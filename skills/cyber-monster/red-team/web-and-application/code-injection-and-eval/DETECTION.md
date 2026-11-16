# Detection Signals and Blue-Team Handoff

> Sub-skill: [`code-injection-and-eval`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application logs where a single request parameter carries arithmetic operators or language keywords immediately before a runtime exception stack frame naming eval or compile.
- Runtime error events citing `SyntaxError`, `ParseError`, or `javax.script.ScriptException` with a statement fragment traceable to request input.
- Interpreter audit hooks (Python `sys.audit` events `compile`/`exec`, PHP `assert` logs) firing on a web-request thread that normally never compiles code.
- Process telemetry showing the web worker spawning a child process seconds after a request to a formula or expression route.
- WAF rule hits for `eval(`, `Function(`, or `preg_replace` modifiers followed by a 200 from the origin on the same path.
- Sudden CPU or wall-clock spikes on an endpoint whose baseline response is a static computed value.
- Outbound connections from the application runtime to an unfamiliar host shortly after a request to a code-evaluation route.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
