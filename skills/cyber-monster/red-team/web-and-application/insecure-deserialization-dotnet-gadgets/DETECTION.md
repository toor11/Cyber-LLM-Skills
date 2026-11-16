# Detection Signals and Blue-Team Handoff

> Sub-skill: [`insecure-deserialization-dotnet-gadgets`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web logs where a `__VIEWSTATE` postback failed MAC validation (ASP.NET event id for ViewState verification failure).
- Repeated `__VIEWSTATE` submissions with altered bytes from one client, indicating forgery attempts.
- `machineKey` values that are identical across multiple hosts or match known default or leaked keys.
- .NET Remoting channels configured with `TypeFilterLevel.Full` in application config.
- Deserialization exceptions naming unexpected types in the worker process (`w3wp`) correlated with request input.
- Child processes spawned by `w3wp` or a remoting host shortly after a ViewState or remoting payload.
- Application logs showing BinaryFormatter or LosFormatter deserializing request-sourced data outside the page lifecycle.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md) | Detection queries, triage, and hardening for this technique |
