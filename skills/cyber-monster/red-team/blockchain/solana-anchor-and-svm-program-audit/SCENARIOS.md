# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`solana-anchor-and-svm-program-audit`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Extra Account Accepted by a Chunked Loop

- **Surface & Preconditions:** An instruction iterates `remaining_accounts` in groups of three with no remainder check.
- **Root Cause & Impact:** A caller appends a fourth account that the loop ignores, or a partial group that changes which accounts are processed.
- **Verification & Fix:** Assert the exact count and reject any length not divisible by the group width, then add a test with a trailing account.

## Case 2: Generic Program Passed to a CPI

- **Surface & Preconditions:** A CPI target is declared as a bare `Program<'info>`, which only proves executability.
- **Root Cause & Impact:** An attacker supplies their own program, which receives the forwarded signer authority and redirects the transfer.
- **Verification & Fix:** Type the callee as `Program<'info, Token>` or compare its key to a constant, and add a test with a substituted program.
