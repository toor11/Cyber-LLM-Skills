# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`erc4626-vault-inflation-and-rounding-audit`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** OpenZeppelin ERC4626 with explicit `Math.Rounding`, and Foundry fuzz tests over the four conversion functions.
- **Validation Gate:** `forge test --match-test testFuzzRoundTrip` plus a donation test asserting the share price is unchanged.
- Override `_decimalsOffset()` rather than the conversion functions when adding a virtual offset; overriding the conversions can silently change a rounding direction.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testVaultRounding -vvv` | Rounding and donation assertions | Cross-platform |
| `cast` | `cast call $VAULT 'convertToShares(uint256)(uint256)' 1000000000000000000` | Read a conversion at a block | Cross-platform |
| `cast` | `cast call $VAULT 'totalAssets()(uint256)'` | Read the asset base the conversions divide by | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

contract VaultMath is Test {
    function testFuzzRoundTrip(uint256 amount) public {
        amount = bound(amount, 1, 1e30);
        uint256 shares = vault.previewDeposit(amount);
        assertLe(vault.previewRedeem(shares), amount, "round trip must not profit");
    }

    function testDonationDoesNotMovePrice() public {
        uint256 before = vault.convertToAssets(1e18);
        deal(address(asset), address(vault), asset.balanceOf(address(vault)) + 1_000e18);
        assertEq(vault.convertToAssets(1e18), before, "donation changed share price");
    }
}
```
