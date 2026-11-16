# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ai-guardrail-and-classifier-bypass`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Encoded Form Passes the Input Filter

- **Surface & Preconditions:** An input classifier is trained on plain text and blocks the plain request.
- **Root Cause & Impact:** The same request base64-encoded passes the filter and the model acts on it.
- **Verification & Fix:** Add encoding normalisation before classification, extend the case set across encoding classes, and retest the blocked and bypass pair.

## Case 2: Output Blocklist Bypassed by Reformulation

- **Surface & Preconditions:** An output filter blocks an exact string.
- **Root Cause & Impact:** A model response that paraphrases the blocked content is released unchanged.
- **Verification & Fix:** Replace the blocklist with a classifier over meaning, keep the blocklist as a second layer, and test reformulations as a case class.
