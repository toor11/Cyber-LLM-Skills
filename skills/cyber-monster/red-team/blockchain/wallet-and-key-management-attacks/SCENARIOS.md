# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`wallet-and-key-management-attacks`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Deadline Parameter Never Enforced

- **Surface & Preconditions:** A permit function accepts a deadline and passes it to the token without comparing it to the block timestamp.
- **Root Cause & Impact:** Expired signatures remain valid indefinitely, so a leaked permit is usable at any later time.
- **Verification & Fix:** Add the timestamp comparison, test that an expired permit reverts, and check every path that accepts a deadline.

## Case 2: Approval to an Upgradeable Spender

- **Surface & Preconditions:** Users grant unlimited approval to a proxy whose implementation can be upgraded.
- **Root Cause & Impact:** A later upgrade changes what the spender can do with the standing authority, without any new user action.
- **Verification & Fix:** Document the trust assumption, prefer time- or amount-bounded approvals, and monitor implementation changes for approval-holding proxies.
