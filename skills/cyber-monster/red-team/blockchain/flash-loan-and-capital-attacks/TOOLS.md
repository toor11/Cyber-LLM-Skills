# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`flash-loan-and-capital-attacks`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Foundry fork test at a pinned block with a flash-loan provider interface or a mock that transfers and requires repayment in the same transaction.
- **Validation Gate:** one test that borrows, acts, and repays atomically, printing the profit.
- Express the attack as one transaction: if it needs two blocks, the capital has to be held and the economics change.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testFlashCapital -vvv --fork-url $RPC --fork-block-number 19000000` | Atomic sequence at a reproducible block | Cross-platform |
| `cast` | `cast call $GOV 'getVotes(address)(uint256)' $ADDR --block $N` | Voting weight at a specific block | Cross-platform |
| `cast` | `cast call $LENDER 'maxFlashLoan(address)(uint256)' $TOKEN` | Available flash liquidity, which bounds the attack size | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

contract FlashCapital is Test {
    function testBorrowAgainstTemporaryBalance() public {
        uint256 before = market.borrowLimit(address(this));
        flashLender.flashLoan(address(this), 1_000_000e18);
        uint256 during = market.borrowLimit(address(this));
        assertEq(during, before, "temporary capital must not raise the limit");
    }
}
```
