# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`eip712-signature-replay-and-account-abstraction`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** EIP-712 typed data with an explicit domain, OpenZeppelin `ECDSA` for recovery, and ERC-4337 `userOpHash` validation rules.
- **Validation Gate:** one replay test and one altered-field test, both asserting rejection.
- ERC-4337 v0.8 includes the EIP-7702 delegation address in the `userOpHash`, so an account validating an older hash definition may accept a mismatched delegation.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `cast` | `cast call $CONTRACT 'DOMAIN_SEPARATOR()(bytes32)'` | Read the domain separator the contract will use | Cross-platform |
| `cast` | `cast wallet sign --private-key $KEY --data $DIGEST` | Produce a test signature for a known digest | Cross-platform |
| `forge` | `forge test --match-test testReplay -vvv` | Assert the second use reverts | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

contract ReplayTest is Test {
    Forwarder fwd;
    uint256 ownerKey = 0xA11CE;
    address owner;

    function setUp() public {
        owner = vm.addr(ownerKey);
        fwd = new Forwarder(owner);
    }

    function testSameSignatureCannotBeReused() public {
        bytes memory sig = _sign(ownerKey, 1 ether, 0);
        fwd.execute(address(0xBEEF), 1 ether, 0, sig);
        vm.expectRevert();
        fwd.execute(address(0xBEEF), 1 ether, 0, sig);
    }
}
```
