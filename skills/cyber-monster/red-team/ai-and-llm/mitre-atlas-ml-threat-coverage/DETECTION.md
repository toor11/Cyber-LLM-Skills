# Detection Signals and Blue-Team Handoff

> Sub-skill: [`mitre-atlas-ml-threat-coverage`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Model artefact downloads from private repositories by principals outside the training pipeline.
- Training-data ingestion from a source without a provenance record.
- Inference API query volume above the per-account baseline, relevant to model-extraction techniques.
- Prompt patterns that probe system instructions, mapped to the corresponding technique.
- Artefact hash mismatches at load, mapped to supply-chain techniques.
- Telemetry retention shorter than the mapping assumes, which invalidates the coverage claim.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
