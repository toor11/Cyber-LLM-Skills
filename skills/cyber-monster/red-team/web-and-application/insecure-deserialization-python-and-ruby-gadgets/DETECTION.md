# Detection Signals and Blue-Team Handoff

> Sub-skill: [`insecure-deserialization-python-and-ruby-gadgets`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- App logs where a request body or cookie base64-decodes to bytes starting with 0x80 (pickle) or 0x04 0x08 (Ruby Marshal).
- YAML parser warnings or exceptions referencing python/object or python/object/apply tags.
- Python tracebacks showing _pickle.UnpicklingError or __reduce__ frames during deserialization of request data.
- EDR or auditd events of the Python or Ruby interpreter PID spawning sh or powershell without a business trigger.
- Rails logs showing Psych or Marshal.load invoked on params, especially in older YAML.load code paths.
- Outbound network connections initiated from the worker process immediately after a request carrying an opaque base64 payload.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`java-spring-security-architecture`](../../../blue-team/application-security/java-spring-security-architecture/SKILL.md) | Detection queries, triage, and hardening for this technique |
