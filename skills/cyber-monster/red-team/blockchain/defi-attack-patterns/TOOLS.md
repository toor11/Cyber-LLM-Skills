# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`defi-attack-patterns`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Foundry fork tests against a pinned block with `--fork-block-number`, so results are reproducible after the pool moves.
- **Validation Gate:** one fork test that demonstrates the atomic sequence and prints the attacker's profit.
- Pin the fork block: an unpinned fork silently changes pool state and makes the test unreproducible.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testAtomicSequence -vvv --fork-url $RPC --fork-block-number 19000000` | Reproducible fork test at a pinned block | Cross-platform |
| `cast` | `cast call $POOL 'slot0()(uint160,int24,uint16,uint16,uint16,uint8,bool)'` | Read pool state to confirm a price input | Cross-platform |
| `slither` | `slither . --detect reentrancy-eth,arbitrary-send-erc20` | Triage for known patterns before manual review | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

contract AtomicSequence is Test {
    function testDonationMovesSharePrice() public {
        uint256 before = vault.convertToAssets(1e18);
        deal(address(token), address(vault), token.balanceOf(address(vault)) + 1_000e18);
        uint256 afterDonation = vault.convertToAssets(1e18);
        assertGt(afterDonation, before, "donation must not change share price");
    }
}
```
