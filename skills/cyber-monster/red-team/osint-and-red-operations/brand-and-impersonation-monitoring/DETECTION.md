# Detection Signals and Blue-Team Handoff

> Sub-skill: [`brand-and-impersonation-monitoring`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Certificate transparency queries for a brand string at high frequency, which is the monitoring programme's own traffic.
- Lookalike domains resolving from a hosting range associated with phishing campaigns.
- Web requests to the genuine site's login page from a hosting address, matching template copying.
- Newly registered lookalike domains appearing in DNS logs of the organisation's own mail gateway.
- Screenshots or page captures stored in bulk by an automation client.
- Registrar API usage enumerating domains matching a pattern.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
