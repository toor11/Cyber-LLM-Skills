# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`foundry-and-echidna-invariant-harness-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Tautological Invariant Shipped as Coverage

- **Surface & Preconditions:** A protocol reports invariant testing coverage from a suite whose properties are all comparisons against zero on unsigned values.
- **Root Cause & Impact:** The suite can never fail, so it provides no assurance and masks the absence of accounting properties.
- **Verification & Fix:** Replace each tautology with a cross-quantity relation, bound the handler, and re-run until either a sequence fails or reached-action coverage is shown.

## Case 2: Unbounded Handler Finding Arithmetic Dead Ends

- **Surface & Preconditions:** The fuzzer reports an invariant violation produced by a deposit of `type(uint256).max`.
- **Root Cause & Impact:** The sequence is unreachable in production because the token's supply is capped, so the counterexample is an artefact of the input domain.
- **Verification & Fix:** Bound the handler to the real supply, re-run, and keep only counterexamples that survive the bound.
