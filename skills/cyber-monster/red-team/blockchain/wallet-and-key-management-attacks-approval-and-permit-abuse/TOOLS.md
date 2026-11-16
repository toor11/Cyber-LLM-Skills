# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`wallet-and-key-management-attacks-approval-and-permit-abuse`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** ERC-20 `allowance`, ERC-721 `isApprovedForAll`, EIP-2612 `permit` with `deadline` and per-owner nonce.
- **Validation Gate:** one allowance read at a pinned block and one expired-permit test asserting a revert.
- Permit signatures are domain-scoped; a missing `chainId` in the domain makes them replayable on a fork.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `cast` | `cast call $TOKEN 'allowance(address,address)(uint256)' $OWNER $SPENDER` | Read the grant at a block | Cross-platform |
| `cast` | `cast call $NFT 'isApprovedForAll(address,address)(bool)' $OWNER $OPERATOR` | Check collection-wide operator approval | Cross-platform |
| `cast` | `cast call $TOKEN 'nonces(address)(uint256)' $OWNER` | Permit nonce, which must advance on use | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import subprocess

TOKEN = "0x0000000000000000000000000000000000000000"
OWNER = "0x0000000000000000000000000000000000000000"
SPENDER = "0x0000000000000000000000000000000000000000"
RPC = "http://127.0.0.1:8545"
allowance = subprocess.run(["cast", "call", TOKEN, "allowance(address,address)(uint256)", OWNER, SPENDER,
                            "--rpc-url", RPC], capture_output=True, text=True).stdout.strip()
nonce = subprocess.run(["cast", "call", TOKEN, "nonces(address)(uint256)", OWNER,
                        "--rpc-url", RPC], capture_output=True, text=True).stdout.strip()
print("allowance", allowance, "nonce", nonce)
```
