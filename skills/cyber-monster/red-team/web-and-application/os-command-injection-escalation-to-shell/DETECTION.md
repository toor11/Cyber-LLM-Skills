# Detection Signals and Blue-Team Handoff

> Sub-skill: [`os-command-injection-escalation-to-shell`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Process-creation events where the web service account spawns an interactive interpreter such as bash -i, python3, or socat.
- Outbound TCP connections from the app tier to uncommon ports immediately after a command-backed request.
- tty allocation or pty.spawn activity under a process whose parent is the web worker.
- auditd execve records for socat, nc, or ncat invoked by the service account.
- DNS lookups for an external host from the app tier preceding an unusual outbound connection.
- Container runtime alerts for a shell being executed inside an image that normally has none.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | Detection queries, triage, and hardening for this technique |
