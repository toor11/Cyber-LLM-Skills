# Detection Signals and Blue-Team Handoff

> Sub-skill: [`red-team-operations-and-scoping`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Inbound connections from an address range outside the client's normal traffic, within a declared window.
- Requests carrying a deconfliction user-agent or marker agreed in the rules of engagement.
- Authentication attempts against enumerated hosts at a rate consistent with a scripted assessment.
- Activity against an excluded address, which is a scope breach the SOC should escalate immediately.
- A single external address probing a narrow host set defined in an engagement document.
- Actions continuing after the window closes, which the action log's scope entries will show.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
