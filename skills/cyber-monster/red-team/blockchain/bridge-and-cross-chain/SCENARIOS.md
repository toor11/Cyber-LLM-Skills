# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`bridge-and-cross-chain`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Message Replayed After Release

- **Surface & Preconditions:** The destination transfers funds based on a validator signature but never records the message id.
- **Root Cause & Impact:** Anyone can resubmit the same message and drain the bridge's liquidity.
- **Verification & Fix:** Record the message id before the transfer, add the replay test, and verify existing messages against the record.

## Case 2: Signature Valid on a Second Deployment

- **Surface & Preconditions:** The digest covers only the amount, so a signature produced for one bridge is valid on a sibling deployment.
- **Root Cause & Impact:** Value is released on a chain the signers never intended, effectively duplicating the transfer.
- **Verification & Fix:** Include the source chain id and destination contract in the digest, and test that a signature for one deployment fails on another.
