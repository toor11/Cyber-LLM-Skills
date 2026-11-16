# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ctf-and-lab-methodology`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Lab or CTF platform access logs showing rapid challenge downloads and submissions.
- Long-running analysis processes on a workstation outside working hours.
- Installation of reverse-engineering or exploitation tooling on a host not designated for it.
- Outbound connections from a lab environment to the public internet, which breaks lab isolation.
- Shared flags or solutions posted from a corporate address.
- Artefact downloads from a CTF platform to a production workstation.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
