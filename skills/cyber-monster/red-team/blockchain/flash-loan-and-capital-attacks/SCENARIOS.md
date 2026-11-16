# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`flash-loan-and-capital-attacks`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Borrow Against a Flash-Funded Balance

- **Surface & Preconditions:** A market checks the caller's token balance rather than a deposited position.
- **Root Cause & Impact:** An attacker flash-borrows the token, passes the collateral check, borrows, and repays the flash loan in the same transaction.
- **Verification & Fix:** Replace the balance check with a deposited and locked position, and add the atomic test as a regression.

## Case 2: Governance Vote With Borrowed Tokens

- **Surface & Preconditions:** Voting weight is read at execution and no snapshot exists.
- **Root Cause & Impact:** A flash loan provides a decisive majority for one block, at the cost of the loan fee.
- **Verification & Fix:** Snapshot voting weight at proposal creation, and test that a balance acquired after the snapshot has no weight.
