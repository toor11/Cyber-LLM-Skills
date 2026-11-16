# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`smart-contract-audit-testing-and-invariants`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Green Invariant With No Coverage

- **Surface & Preconditions:** A protocol reports invariant coverage from a suite whose handler is never called.
- **Root Cause & Impact:** The campaign explored nothing, so the passing result carries no assurance.
- **Verification & Fix:** Check reached-handler coverage, add a handler with real actions, and re-run until either a sequence fails or coverage is demonstrated.

## Case 2: Fork Test That Changes With the Chain

- **Surface & Preconditions:** A fork test passes in review and fails a week later.
- **Root Cause & Impact:** No block number was pinned, so the underlying state moved.
- **Verification & Fix:** Pin `--fork-block-number`, re-run both the baseline and the probe at that block, and record the block in the finding.
