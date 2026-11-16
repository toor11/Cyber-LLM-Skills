# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`model-and-artifact-supply-chain`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Pickle Artefact From a Moved Tag

- **Surface & Preconditions:** A deployment pulls `pytorch_model.bin` from a repository tag that the owner can move.
- **Root Cause & Impact:** The loaded file can execute code in the inference host, and the model card does not prevent it.
- **Verification & Fix:** Convert to `safetensors`, record the hash in the deployment manifest, verify at load, and pin the artefact rather than the tag.

## Case 2: Tokenizer Swapped Without a Weights Change

- **Surface & Preconditions:** The tokenizer is fetched from the same namespace but is not covered by the hash check.
- **Root Cause & Impact:** Model behaviour changes with the same weights, which is enough to alter output in ways the review never saw.
- **Verification & Fix:** Treat the tokenizer and config as artefacts with their own hashes, verify all of them, and fail the deployment on any mismatch.
