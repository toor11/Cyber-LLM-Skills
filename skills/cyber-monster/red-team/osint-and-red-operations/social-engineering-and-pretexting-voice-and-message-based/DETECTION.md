# Detection Signals and Blue-Team Handoff

> Sub-skill: [`social-engineering-and-pretexting-voice-and-message-based`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Inbound calls to a service desk from an internal extension with no prior history, requesting account changes.
- Requests for a reset where the caller declines or avoids a callback.
- Caller ID values matching an approved assessment identity, recorded in the telephony log.
- A cluster of reset requests for accounts in one department within minutes.
- Calls ending abruptly after the agent asks for a callback number.
- Message-based contacts referencing urgency or a manager's authority in the body text.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
