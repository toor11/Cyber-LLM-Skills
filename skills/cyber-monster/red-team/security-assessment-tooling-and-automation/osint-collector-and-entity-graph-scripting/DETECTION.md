# Detection Signals and Blue-Team Handoff

> Sub-skill: [`osint-collector-and-entity-graph-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- API key usage against OSINT providers from a single address exceeding the licensed quota.
- Automated collection user-agents hitting archive and registry endpoints in sequence.
- SQLite databases with tables named after OSINT providers appearing on endpoint storage.
- Repeated queries for the same identifier at a fixed interval, characteristic of a scheduled collector.
- Access to breach-data or corporate-registry APIs from a host outside the research subnet.
- Egress to many unrelated data providers from one process within minutes, matching a multi-source collector.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
