# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`wallet-and-key-management-attacks-approval-and-permit-abuse`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Permit Grants the Full Balance

- **Surface & Preconditions:** A staking contract submits a permit for `type(uint256).max` on behalf of the user.
- **Root Cause & Impact:** The user's entire balance is spendable by the contract indefinitely, far beyond the stake amount.
- **Verification & Fix:** Approve exactly the amount being staked, enforce the deadline in the calling contract, and test that a permit for a past deadline reverts.

## Case 2: Approval to an Upgradeable Spender

- **Surface & Preconditions:** A router proxy holds unlimited approvals and its implementation can be upgraded.
- **Root Cause & Impact:** An upgrade changes what the standing authority can do without any user action.
- **Verification & Fix:** Document the trust assumption, prefer bounded approvals with a reset, and monitor implementation changes for approval-holding proxies.
