# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`defi-attack-patterns-lending-and-collateral`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: No Buffer Between Borrow and Liquidation

- **Surface & Preconditions:** The collateral factor and the liquidation threshold are both 80%.
- **Root Cause & Impact:** A borrower at maximum LTV is liquidatable on the next tick, losing the bonus to any liquidator.
- **Verification & Fix:** Lower the collateral factor to create a buffer, test the health factor after a realistic adverse move, and document the remaining margin.

## Case 2: Undefined Bad Debt

- **Surface & Preconditions:** A position's collateral falls below its debt and liquidation reverts because the bonus exceeds the collateral.
- **Root Cause & Impact:** The loss has no defined owner and is silently absorbed by depositors.
- **Verification & Fix:** Cap the seizure at available collateral, emit a bad-debt event for the remainder, and add the event to the monitoring set.
