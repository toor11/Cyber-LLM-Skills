# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`foundry-and-echidna-invariant-harness-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Foundry 1.x invariant testing with `StdInvariant`, `targetContract`, `bound`; Echidna 2.x property naming.
- **Validation Gate:** `forge test --match-contract <InvariantContract> -vv` plus one replay of the exported counterexample.
- Foundry's 1.x releases added persistent corpus directories and replay subcommands for fuzz and invariant campaigns; separate corpus paths per campaign keep counterexamples attributable.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-contract Invariant -vv` | Run the stateful property campaign and print the failing call sequence | Cross-platform |
| `forge fuzz replay` | `forge fuzz replay --corpus-dir cache/inv-corpus` | Replay persisted campaign inputs without starting a new campaign | Cross-platform |
| `echidna` | `echidna test/Invariant.sol --contract VaultInvariant --test-limit 50000` | Second search strategy against the same property | Linux, macOS, Windows WSL |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";

contract Handler is Test {
    uint256 public ghost_deposits;
    function deposit(uint256 amt) public {
        amt = bound(amt, 1, 1e18);
        ghost_deposits += amt;
    }
}

contract Props is StdInvariant, Test {
    Handler handler;
    function setUp() public {
        handler = new Handler();
        targetContract(address(handler));
    }
    function invariant_ghostTracksDeposits() public view {
        assertGe(handler.ghost_deposits(), 0);
        assertLe(handler.ghost_deposits(), 1e18 * 1e6);
    }
}
```
