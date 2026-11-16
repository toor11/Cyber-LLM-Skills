# Detection Signals and Blue-Team Handoff

> Sub-skill: [`multimodal-and-vision-llm-injection`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Uploads whose extracted text differs substantially from the visible page content.
- OCR text containing imperative sentences addressed to a model.
- Images or PDFs with annotations, hidden layers, or off-page text reaching extraction.
- Tool calls immediately following a document upload and analysis.
- Audio transcripts containing instruction-like phrases.
- A rise in upload volume from one account with similar documents, characteristic of a payload search.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
