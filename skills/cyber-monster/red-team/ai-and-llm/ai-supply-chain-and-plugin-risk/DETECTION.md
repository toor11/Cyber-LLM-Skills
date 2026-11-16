# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ai-supply-chain-and-plugin-risk`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Plugin manifest hash changing without a corresponding approval record.
- Plugin calls using a service account for actions attributed to an individual user.
- Plugin endpoints contacted outside the configured allowlist.
- A plugin description containing imperative text addressed to the model.
- New plugins appearing in the runtime inventory without a deployment change.
- Plugin responses that contain instructions rather than data.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
