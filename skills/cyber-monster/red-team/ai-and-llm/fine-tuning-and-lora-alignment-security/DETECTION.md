# Detection Signals and Blue-Team Handoff

> Sub-skill: [`fine-tuning-and-lora-alignment-security`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Adapter artefacts loaded at inference whose hash is absent from the deployment manifest.
- A drop in refusal rate after a model deployment, visible in output sampling.
- Training datasets created from user content without a provenance or deduplication step.
- New adapters appearing in a shared model cache without a corresponding pipeline run.
- Canary strings appearing in model outputs.
- Model behaviour changing for a narrow trigger while a general evaluation set is unchanged.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
