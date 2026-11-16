# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`erc4626-vault-inflation-and-rounding-audit`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Donation Inflates the First Depositor's Share

- **Surface & Preconditions:** A vault derives `totalAssets()` from its token balance and sets no virtual offset.
- **Root Cause & Impact:** The first depositor mints one wei of shares, donates assets, and the next depositor's deposit is rounded to zero shares.
- **Verification & Fix:** Track assets internally or set a decimals offset with a minimum initial deposit, and add the donation test as a regression.

## Case 2: Inverted Rounding on Withdraw

- **Surface & Preconditions:** An override computes `previewWithdraw` with `Math.Rounding.Floor`.
- **Root Cause & Impact:** Each withdrawal burns fewer shares than the assets released, so the remaining holders subsidise every exit.
- **Verification & Fix:** Restore `Ceil` on `previewWithdraw`, add a fuzz test asserting the vault-favouring direction, and check the other three conversions in the same pass.
