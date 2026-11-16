# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssrf-protocol-smuggling`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application or proxy logs where a url or source parameter begins with gopher://, dict://, file://, ldap://, or tftp://.
- Outbound TCP from the application host to internal service ports carrying non-HTTP payloads.
- File-read events on the application host for paths that match request parameters.
- UDP requests from the web tier consistent with a tftp fetch.
- Connector exceptions naming unsupported schemes, indicating scheme values reaching the URL library.
- Connections from the app tier to memcached or redis ports following a request with a crafted scheme.
- URL-library handler initialisation for file or gopher in application runtime logs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) | Detection queries, triage, and hardening for this technique |
