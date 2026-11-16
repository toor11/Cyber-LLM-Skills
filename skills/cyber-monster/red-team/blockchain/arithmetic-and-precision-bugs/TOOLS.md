# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`arithmetic-and-precision-bugs`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Solidity 0.8.x checked arithmetic, OpenZeppelin `Math.mulDiv` with an explicit `Rounding`, Foundry fuzz tests with `bound`.
- **Validation Gate:** a fuzz test that pins the rounding direction for both share and asset conversions.
- `mulDiv` with 512-bit intermediate precision avoids the overflow that makes naive `a * b / c` unusable for large values.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testFuzzDecimals -vvv` | Fuzz over amounts and decimal values | Cross-platform |
| `cast` | `cast call $TOKEN 'decimals()(uint8)'` | Read the token decimals instead of assuming 18 | Cross-platform |
| `chisel` | `chisel` | Evaluate integer expressions interactively when checking truncation | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

contract RoundingTest is Test {
    function testFuzzSharesNeverExceedAssets(uint256 amount, uint256 price) public {
        amount = bound(amount, 1, 1e30);
        price = bound(price, 1e6, 1e30);
        uint256 shares = vault.previewDeposit(amount);
        assertLe(shares, amount, "shares must not exceed assets");
        assertGe(vault.previewRedeem(shares), 0);
    }
}
```
