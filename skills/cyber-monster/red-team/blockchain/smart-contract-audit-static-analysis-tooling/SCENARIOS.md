# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`smart-contract-audit-static-analysis-tooling`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Report Dominated by Library Findings

- **Surface & Preconditions:** A delivered report lists twenty items, eighteen of them in a forked dependency.
- **Root Cause & Impact:** The run was unfiltered, and dependencies are not the client's code.
- **Verification & Fix:** Scope the run to project paths, report dependency issues only when a pin or patch is available, and re-triage the two real items.

## Case 2: Detector Hit With No Caller

- **Surface & Preconditions:** A reentrancy detector fires on an internal function that only a guarded path can reach.
- **Root Cause & Impact:** Reachability was never checked, so the item was reported as exploitable.
- **Verification & Fix:** Trace the caller set, note the guard, and either dismiss the item with the reason or report it as a note about defence in depth.
