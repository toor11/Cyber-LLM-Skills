# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`governance-and-token-attacks`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Proposal Decided With Borrowed Weight

- **Surface & Preconditions:** Vote weight is read when the proposal executes and there is no snapshot.
- **Root Cause & Impact:** An attacker borrows the token, votes, and repays, having decided the proposal for the loan fee.
- **Verification & Fix:** Snapshot weight at proposal creation, test that a later acquisition has no weight, and re-run the capture-cost calculation with the new mechanism.

## Case 2: Same-Block Deposit Claims Rewards

- **Surface & Preconditions:** Rewards accrue per block and the claim reads the live balance.
- **Root Cause & Impact:** A deposit made in the distribution block claims rewards accrued before it existed.
- **Verification & Fix:** Checkpoint rewards with an index and per-account debt, and add the same-block test as a regression.
