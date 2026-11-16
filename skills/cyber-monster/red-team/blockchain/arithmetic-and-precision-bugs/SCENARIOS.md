# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`arithmetic-and-precision-bugs`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Truncation to Zero on Small Principals

- **Surface & Preconditions:** A reward function divides by 1e18 before multiplying by the rate.
- **Root Cause & Impact:** Any principal below one token earns exactly zero, which is a silent loss for small holders.
- **Verification & Fix:** Reorder the arithmetic to multiply first, add a fuzz test over small amounts, and assert the reward is non-zero whenever the exact value exceeds one wei.

## Case 2: Six-Decimal Token in an Eighteen-Decimal Formula

- **Surface & Preconditions:** A protocol assumes 18 decimals and a supported token has 6.
- **Root Cause & Impact:** Every computed amount is wrong by 10^12, which either overpays or bricks withdrawals.
- **Verification & Fix:** Read `decimals()` per token, normalise explicitly, and fuzz the conversion across the supported decimal range.
