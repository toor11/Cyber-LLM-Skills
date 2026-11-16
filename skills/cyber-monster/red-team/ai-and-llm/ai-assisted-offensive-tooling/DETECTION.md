# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ai-assisted-offensive-tooling`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Deliverables containing CVE identifiers with no corresponding advisory reference in the evidence store.
- Payloads in a report that differ from the reviewed probe set, indicating an unverified model draft was used.
- Model API calls containing client data from an unapproved service.
- Assist logs with prompts but no verification entries for the same task.
- Scanner findings grouped by a narrative that does not match the scanner's own categories.
- Bulk generated payloads executed against a target in one window.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
