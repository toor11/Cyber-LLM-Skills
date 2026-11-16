# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`governance-and-token-attacks`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Foundry tests over the proposal lifecycle, checkpoint reads at specific blocks, and a reward index with per-account debt.
- **Validation Gate:** one test asserting a post-snapshot balance has no vote weight, and one asserting a same-block deposit earns nothing.
- Timelock duration is part of the security budget; record it with the threshold and price in the cost calculation.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testGovernanceCapture -vvv` | Proposal lifecycle and capture-cost assertions | Cross-platform |
| `cast` | `cast call $GOV 'quorum()(uint256)' --rpc-url $RPC` | Read the quorum requirement | Cross-platform |
| `cast` | `cast call $TOKEN 'balanceOfAt(address,uint256)(uint256)' $ADDR $BLOCK` | Vote weight at the snapshot block | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import subprocess

GOV = "0x0000000000000000000000000000000000000000"
TOKEN = "0x0000000000000000000000000000000000000000"
RPC = "http://127.0.0.1:8545"
threshold = subprocess.run(["cast", "call", GOV, "threshold()(uint256)", "--rpc-url", RPC],
                           capture_output=True, text=True).stdout.split()[0]
print("threshold", threshold)
print("cost = threshold * token price; compare with the value a proposal can move")
```
