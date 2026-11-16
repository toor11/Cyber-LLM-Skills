# Detection Signals and Blue-Team Handoff

> Sub-skill: [`os-command-injection-shell-metacharacter-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Request parameters containing ${IFS}, $IFS$9, or brace sequences like {a,b} on a command-backed route.
- Command lines in process telemetry that include IFS references or glob patterns such as /???/ reconstructing binaries.
- WAF events that strip a separator followed by a 200 from the origin, indicating the payload still executed.
- execve records whose argv shows quote- or backslash-split keywords rejoined into a known command.
- A burst of requests cycling through encoding and substitution variants of the same base command.
- Application logs showing a blocked direct command immediately followed by a succeeding equivalent from the same session.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | Detection queries, triage, and hardening for this technique |
