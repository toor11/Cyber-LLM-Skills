# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`llm-jailbreak-and-guardrails`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Bypass Before the Output Filter

- **Surface & Preconditions:** A framing gets past the model's refusal, and the output filter then blocks the response.
- **Root Cause & Impact:** The chain held, and the finding is the model-level gap rather than a user-visible impact.
- **Verification & Fix:** Record it as a defence-in-depth observation, retest after the next model upgrade, and keep the filter in the loop for future tests.

## Case 2: Escalation Across Turns

- **Surface & Preconditions:** A stateless single-turn request is refused, and the same goal succeeds when spread over five turns.
- **Root Cause & Impact:** The application retains conversation state, which the escalation relies on.
- **Verification & Fix:** Add per-turn policy evaluation or reset context at a boundary, and test the multi-turn case as a regression.
