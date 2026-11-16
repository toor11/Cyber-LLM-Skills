# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ml-adversarial-and-data-poisoning`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Predict requests with small pixel or token perturbations across a large number of queries from one client.
- Query volumes far above normal for an endpoint that returns probability vectors.
- Training-data ingestion from a new source whose labels differ systematically from existing data.
- A model's output changing for a specific input pattern while accuracy on the general set is unchanged.
- Gradient or logit endpoints accessed by accounts that only need labels.
- Dataset versions created outside the normal pipeline, visible as uncommitted data changes.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
