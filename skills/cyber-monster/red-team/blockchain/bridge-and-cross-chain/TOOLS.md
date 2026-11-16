# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`bridge-and-cross-chain`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Solidity with an explicit message struct, `abi.encode` for the digest (not `encodePacked` with dynamic types), and a processed-message mapping.
- **Validation Gate:** a replay test that reverts and a wrong-source test that reverts, both in Foundry.
- `abi.encodePacked` with two dynamic types is ambiguous; use `abi.encode` for digests to avoid hash collisions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testBridgeReplay -vvv` | Assert duplicate submissions revert | Cross-platform |
| `cast` | `cast abi-encode 'f(uint256,address,bytes32,address,uint256)' ...` | Reproduce the digest off-chain to compare with the contract | Cross-platform |
| `cast` | `cast keccak 0x...` | Hash the encoded message exactly as the contract does | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import subprocess

BRIDGE = "0x0000000000000000000000000000000000000000"
RPC = "http://127.0.0.1:8545"
enc = subprocess.run(["cast", "abi-encode", "f(uint256,address,bytes32,address,uint256)",
                      "1", BRIDGE, "0x" + "00" * 32, BRIDGE, str(10**18)],
                     capture_output=True, text=True, check=True).stdout.strip()
print(enc)
```
