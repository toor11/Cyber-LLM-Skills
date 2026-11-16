# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`oracle-and-price-manipulation`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Stale Feed Prices a Borrow

- **Surface & Preconditions:** A lending market accepts a feed answer that is two days old because only the answer is read.
- **Root Cause & Impact:** The borrow limit reflects a price that no longer exists, and the position is under-collateralised from the moment it opens.
- **Verification & Fix:** Add the `updatedAt` and `answeredInRound` checks with a stated maximum staleness, and test that an old answer reverts.

## Case 2: Decimals Assumed Rather Than Read

- **Surface & Preconditions:** A feed returns 8 decimals and the protocol divides by 1e18.
- **Root Cause & Impact:** Every collateral value is off by ten orders of magnitude, making limits and liquidations meaningless.
- **Verification & Fix:** Read `decimals()` from the feed and scale explicitly, then add a test that pins the expected value for a known answer.
