# Detection Signals and Blue-Team Handoff

> Sub-skill: [`prototype-pollution-rce-chains`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Process spawn audit events where the child environment contains keys the application never set.
- NODE_OPTIONS present in a child process environment without a matching deployment config.
- Template render errors occurring immediately after a prototype-pollution request.
- APM spans showing execFile or spawn invoked with inherited rather than explicit options.
- Request bodies carrying __proto__.env or __proto__.outputFunctionName keys.
- auditd EXECVE events by the Node service user following a pollution POST.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
