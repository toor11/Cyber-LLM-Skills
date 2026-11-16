# Detection Signals and Blue-Team Handoff

> Sub-skill: [`social-engineering-and-pretexting-email-and-credential-phishing`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Inbound mail whose From domain is a lookalike of an internal domain, visible in the mail gateway's domain similarity check.
- Link clicks to a domain registered within the last 30 days from internal recipients.
- A cluster of recipients replying to the same external address within minutes.
- Landing page requests with an empty or stripped request body, characteristic of an event-only capture.
- Help-desk tickets reporting a suspicious email, which should be correlated with the sending domain.
- Authentication failures following a wave of password-entry events against a non-corporate domain.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
