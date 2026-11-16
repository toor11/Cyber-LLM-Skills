# Detection Signals and Blue-Team Handoff

> Sub-skill: [`os-command-injection-argument-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- execve audit records where a child tool receives an argument beginning with a dash that originated from request input.
- curl or wget invocations logged with -o, --output, or -K flags that the application never sets itself.
- git process arguments containing --upload-pack or an inherited GIT_SSH_COMMAND environment variable.
- New files written to unexpected paths immediately after a media or download request, indicating an output-option redirect.
- ImageMagick or ffmpeg child processes opening delegate helpers or non-local protocols.
- Argument vectors in process telemetry that lack a `--` separator between fixed flags and user-derived values.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | Detection queries, triage, and hardening for this technique |
