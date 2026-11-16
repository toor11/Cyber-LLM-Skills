# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`llm-denial-of-service-and-cost`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Client-Set Output Cap

- **Surface & Preconditions:** The request body carries `max_tokens` and the server passes it through.
- **Root Cause & Impact:** A caller sets the provider maximum and multiplies cost per request without triggering any limit.
- **Verification & Fix:** Enforce a server-side cap, ignore client values above it, add a per-user token quota, and re-measure the worst case.

## Case 2: Agent Loop Without a Counter

- **Surface & Preconditions:** An agent continues while the model returns tool calls.
- **Root Cause & Impact:** A prompt that induces repeated tool calls runs until the provider or budget gives out.
- **Verification & Fix:** Add a step counter and a total token budget, return a bounded message on exhaustion, and test with an inducing prompt.
