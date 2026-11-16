# Detection Signals and Blue-Team Handoff

> Sub-skill: [`bug-bounty-target-prioritization`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Automated enumeration of an API surface at rates above the programme's published limits.
- Requests to endpoints documented but not yet in the public client, indicating change-driven research.
- Multiple researchers hitting the same new path within hours, visible as distinct client fingerprints on one route.
- Scans for excluded issue classes, which the programme's own triage will close as informative.
- Out-of-scope asset access from a researcher address, a policy violation the programme tracks.
- Repeated authentication failures against a v3 endpoint, characteristic of authorisation probing.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
