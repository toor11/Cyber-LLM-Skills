# Detection Signals and Blue-Team Handoff

> Sub-skill: [`social-engineering-and-pretexting`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Calls to a service desk from an internal extension that has no prior history with the team.
- Password reset requests for accounts whose owner is on leave, from a colleague rather than the owner.
- Email arriving from a lookalike domain shortly before a verification-sensitive request.
- A cluster of identity-verification events for one department within a short window.
- Callback requests to numbers that differ from the directory record.
- Help-desk tickets referencing urgency or authority pressure in their text.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
