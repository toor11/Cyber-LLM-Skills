# Detection Signals and Blue-Team Handoff

> Sub-skill: [`path-traversal-and-lfi`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs where a file, path, or template parameter contains ../ sequences, a leading /, or a Windows drive letter.
- Requests whose path parameter begins with \\ indicating a UNC or network-path attempt.
- Web process file opens outside the configured content root recorded by auditd or EDR file telemetry.
- A single session requesting incrementally deeper ../ ladders against the same parameter.
- Responses returning the contents of system files such as /etc/hostname or win.ini on a download route.
- PHP include or require events whose filename argument contains request-derived path segments.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) | Detection queries, triage, and hardening for this technique |
