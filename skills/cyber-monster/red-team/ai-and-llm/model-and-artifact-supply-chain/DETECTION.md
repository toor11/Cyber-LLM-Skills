# Detection Signals and Blue-Team Handoff

> Sub-skill: [`model-and-artifact-supply-chain`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Model downloads from a namespace that differs from the one in the deployment manifest.
- Artefact hash mismatches at load time, even when a retry succeeds.
- `torch.load` or `pickle.load` calls in an inference container's process tree.
- A tokenizer or config file modified without a corresponding weights change.
- Outbound model-hub traffic from an inference host that should only read from a local cache.
- New artefacts appearing in a shared cache directory without a corresponding pipeline run.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
