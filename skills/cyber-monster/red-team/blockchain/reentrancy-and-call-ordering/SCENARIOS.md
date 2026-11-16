# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`reentrancy-and-call-ordering`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Double Withdrawal via a Receiver Contract

- **Surface & Preconditions:** A vault sends ETH before reducing the caller's balance.
- **Root Cause & Impact:** A receiver contract re-enters withdraw and receives a second payout against the unreduced balance.
- **Verification & Fix:** Write the balance before the call, add the guard, and keep the malicious-receiver test as a regression.

## Case 2: Read-Only Reentrancy Through a Stale Price

- **Surface & Preconditions:** A lending protocol reads a vault's price view during a callback, and the view reflects a mid-transaction balance.
- **Root Cause & Impact:** The borrower's collateral is valued at a temporarily inflated price, enabling an over-borrow.
- **Verification & Fix:** Make the view derive from accounted state rather than live balance, and add a test asserting the view is identical inside and outside the callback.
