# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`access-control-and-initialization`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** OpenZeppelin `Initializable` and `AccessControl`, proxy patterns with EIP-1967 slots, Foundry prank-based access tests.
- **Validation Gate:** one revert assertion per privileged function plus one initialiser assertion on both proxy and implementation.
- Grant roles in the initialiser rather than a separate transaction; a gap between deployment and role grant is an exploitable window.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testAccessControl -vvv` | Assert revert for unauthorised callers | Cross-platform |
| `cast` | `cast storage $PROXY $ADMIN_SLOT --rpc-url $RPC` | Read the proxy admin authority | Cross-platform |
| `cast` | `cast call $CONTRACT 'hasRole(bytes32,address)(bool)' $ROLE $ADDR` | Check a specific role grant | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

contract AccessTest is Test {
    Vault vault;
    address admin = address(0xA11CE);
    address attacker = address(0xBAD);

    function setUp() public {
        vault = new Vault();
        vault.initialize(admin);
    }

    function testUnauthorisedCannotSetFee() public {
        vm.prank(attacker);
        vm.expectRevert();
        vault.setFee(1);
    }
}
```
