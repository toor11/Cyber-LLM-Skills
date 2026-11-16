# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`wallet-and-key-management-attacks`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `cast` for allowance and signature calls, EIP-712 domain review (`chainId`, `verifyingContract`), and a key-generation entropy review.
- **Validation Gate:** one allowance read at a pinned block and one signature replay attempt.
- EIP-2612 permits are chain- and contract-scoped through the domain separator; a missing `chainId` in the domain makes the signature replayable across forks.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `cast` | `cast call $TOKEN 'allowance(address,address)(uint256)' $OWNER $SPENDER` | Read standing authority at a block | Cross-platform |
| `cast` | `cast call $CONTRACT 'DOMAIN_SEPARATOR()(bytes32)'` | Read the EIP-712 domain separator | Cross-platform |
| `cast` | `cast wallet address --private-key $KEY` | Confirm the address a key controls during lab work | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import subprocess

TOKEN = "0x0000000000000000000000000000000000000000"
OWNER = "0x0000000000000000000000000000000000000000"
SPENDER = "0x0000000000000000000000000000000000000000"
RPC = "http://127.0.0.1:8545"
out = subprocess.run(["cast", "call", TOKEN, "allowance(address,address)(uint256)", OWNER, SPENDER,
                      "--rpc-url", RPC], capture_output=True, text=True, check=True).stdout.strip()
print("allowance", out)
```
