# Detection Signals and Blue-Team Handoff

> Sub-skill: [`report-writing-and-findings`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Report submissions whose reproduction steps reference internal hostnames, indicating a finding that cannot be verified externally.
- Repeat submissions of the same title, characteristic of a duplicate that was not searched first.
- Findings rated critical with no stated precondition, which the triage queue flags for review.
- Evidence attachments without timestamps or hashes.
- Reports that include captured credentials or personal data, a data-handling incident.
- A cluster of findings against one endpoint suggesting a systematic control gap rather than individual bugs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
