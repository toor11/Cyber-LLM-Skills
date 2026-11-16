# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`defi-attack-patterns-amm-and-liquidity`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Foundry fork tests at a pinned block with the pool invariant asserted in the test body.
- **Validation Gate:** one test asserting the invariant after a swap, and one asserting `amountOutMin` is enforced.
- Pin the fork block; pool reserves change every block and an unpinned test is not reproducible.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testPoolInvariant -vvv --fork-block-number 19000000` | Invariant assertions at a reproducible block | Cross-platform |
| `cast` | `cast call $POOL 'getReserves()(uint112,uint112,uint32)'` | Read reserves for the invariant calculation | Cross-platform |
| `cast` | `cast call $POOL 'totalSupply()(uint256)'` | Share supply, needed for the mint-inflation check | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

contract PoolInvariant is Test {
    function testSwapPreservesK() public {
        (uint112 r0, uint112 r1, ) = pool.getReserves();
        uint256 kBefore = uint256(r0) * uint256(r1);
        pool.swap(1e18, 0, block.timestamp + 60, true);
        (uint112 n0, uint112 n1, ) = pool.getReserves();
        uint256 kAfter = uint256(n0) * uint256(n1);
        assertGe(kAfter, kBefore, "k decreased");
    }
}
```
