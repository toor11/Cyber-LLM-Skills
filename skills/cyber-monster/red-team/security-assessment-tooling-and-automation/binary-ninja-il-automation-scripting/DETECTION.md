# Detection Signals and Blue-Team Handoff

> Sub-skill: [`binary-ninja-il-automation-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Headless Binary Ninja license check-in traffic from an analysis host, naming the product version.
- `.bndb` database creation events on a share holding production binaries, which marks an unauthorised analysis attempt.
- Long-running analysis processes with high RSS and a single open database file.
- Python process command lines referencing a binaryninja import on hosts that never reverse engineer.
- Script console history or plugin load events inside the Binary Ninja user directory.
- Database files appearing beside a build artefact, indicating an analyst copied a production binary off its host.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
