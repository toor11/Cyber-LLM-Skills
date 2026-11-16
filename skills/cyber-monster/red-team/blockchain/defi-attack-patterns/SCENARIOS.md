# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`defi-attack-patterns`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Collateral Priced From Spot Reserves

- **Surface & Preconditions:** A lending contract values collateral using a pair's instantaneous reserves.
- **Root Cause & Impact:** An attacker swaps to move the reserves, borrows against the inflated collateral, and swaps back within one transaction.
- **Verification & Fix:** Replace the spot read with a time-weighted quote over a stated window, and add a fork test that shows the manipulated quote no longer changes the borrow limit.

## Case 2: Donation Inflates Share Price

- **Surface & Preconditions:** A vault derives share price from its token balance, and a direct transfer changes it.
- **Root Cause & Impact:** The first depositor or a donor can make later deposits worth fewer shares, capturing value from subsequent depositors.
- **Verification & Fix:** Track assets internally, update only on deposit and withdraw, and add an invariant test that a direct transfer leaves share price unchanged.
