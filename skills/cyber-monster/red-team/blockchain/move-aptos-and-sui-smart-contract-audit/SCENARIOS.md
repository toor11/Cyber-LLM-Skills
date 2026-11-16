# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`move-aptos-and-sui-smart-contract-audit`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Copyable Token Breaks Supply

- **Surface & Preconditions:** A token struct declares `copy`, and a holder duplicates a balance.
- **Root Cause & Impact:** The module's recorded supply no longer matches the sum of held balances, and the duplicate can be sold.
- **Verification & Fix:** Remove `copy` and `drop` from the value-carrying struct, add a test that the resource cannot be copied, and re-check every function that assumed supply equals minted minus burned.

## Case 2: Forged Capability Grants Mint Authority

- **Surface & Preconditions:** A capability struct has public fields and no module-only constructor.
- **Root Cause & Impact:** An external module constructs the capability and calls `mint`, creating tokens without authority.
- **Verification & Fix:** Make the fields private, create the capability only in the module's initialiser, and require a module-owned reference in the mint function.
