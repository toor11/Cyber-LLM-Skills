# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ml-adversarial-and-data-poisoning`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Probability Vectors Enable Cheap Perturbation

- **Surface & Preconditions:** A classification endpoint returns full class probabilities to every caller.
- **Root Cause & Impact:** An attacker searches for a minimal perturbation using the returned distributions at a low query cost.
- **Verification & Fix:** Return only the label and confidence to untrusted callers, rate-limit per account, and test that the perturbation search no longer converges within the budget.

## Case 2: Small Poisoned Fraction With a Trigger

- **Surface & Preconditions:** Training data includes user-submitted examples with no provenance tracking.
- **Root Cause & Impact:** A small set of examples containing a chosen trigger shifts behaviour for that trigger only.
- **Verification & Fix:** Add provenance and deduplication to the ingestion path, evaluate on triggered and untriggered subsets, and require a human review for new sources.
