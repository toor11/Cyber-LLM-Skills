# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`smart-contract-audit-testing-and-invariants`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Foundry invariant testing (`StdInvariant`, `targetContract`, `bound`), fork tests with `--fork-block-number`, and corpus directories for replay.
- **Validation Gate:** one invariant test with reached-handler coverage shown, and one fork test pinned to a block.
- Foundry's 1.x releases added corpus persistence, replay subcommands, and symbolic preview modes; separate corpus paths per campaign keep failures attributable.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-contract Props -vv` | Run the invariant campaign with a trace | Cross-platform |
| `forge` | `forge fuzz replay --corpus-dir cache/inv-corpus` | Replay persisted campaign inputs | Cross-platform |
| `forge` | `forge test --fork-url $RPC --fork-block-number 19000000` | Reproducible test against deployed state | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";

contract Handler is Test {
    Vault vault;
    constructor(Vault v) { vault = v; }

    function deposit(uint256 amt) public {
        amt = bound(amt, 1, 1e24);
        vault.deposit(amt, address(this));
    }

    function withdraw(uint256 amt) public {
        amt = bound(amt, 0, vault.balanceOf(address(this)));
        vault.withdraw(amt, address(this), address(this));
    }
}

contract Props is StdInvariant, Test {
    Vault vault;
    function setUp() public {
        vault = new Vault();
        targetContract(address(new Handler(vault)));
    }
    function invariant_assetsCoverShares() public view {
        assertGe(vault.totalAssets(), vault.totalSupply());
    }
}
```
