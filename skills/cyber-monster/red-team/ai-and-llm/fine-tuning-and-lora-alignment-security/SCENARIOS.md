# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`fine-tuning-and-lora-alignment-security`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Adapter Suppresses Refusals

- **Surface & Preconditions:** A style adapter from a public repository is loaded without evaluation.
- **Root Cause & Impact:** Refusal behaviour on unrelated policy classes is reduced, and the change appears only in production traffic.
- **Verification & Fix:** Verify the adapter hash, run the safety evaluation against base and tuned artefacts, and block the deployment on any regression.

## Case 2: Canary Reproduced From Training Data

- **Surface & Preconditions:** A canary inserted into a fine-tuning dataset appears in model output.
- **Root Cause & Impact:** The model retained verbatim training data, which means other user content may be extractable too.
- **Verification & Fix:** Increase deduplication, remove the offending data, retrain, and re-run the canary probe across several prompt forms.
