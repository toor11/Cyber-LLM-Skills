# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`defi-attack-patterns-amm-and-liquidity`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Rounding Leak on Every Swap

- **Surface & Preconditions:** A pool computes the output with an integer division that favours the trader by one wei.
- **Root Cause & Impact:** Each swap leaks a wei to the trader, and a bot repeating it drains the pool slowly.
- **Verification & Fix:** Add the `k` check after the trade, confirm the invariant holds within tolerance, and test with a fuzz over amounts.

## Case 2: First Provider Sets an Extreme Share Price

- **Surface & Preconditions:** The initial deposit mints shares with no minimum and no burned position.
- **Root Cause & Impact:** The first provider can make later deposits worth almost nothing, capturing their value.
- **Verification & Fix:** Burn a minimum liquidity amount on first mint, require a minimum initial deposit, and test that a second depositor receives a proportional share.
