# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cryptocurrency-and-onchain-tracing-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** chain RPC via `cast` or an explorer API; read receipts and logs rather than relying on explorer labels.
- **Validation Gate:** one hop traced end to end with a transaction hash and block height for each side.
- Record the chain id with every observation: the same address string exists on every EVM chain.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `cast` | `cast receipt 0xabc --rpc-url $RPC` | Read a transaction receipt and its logs | Cross-platform |
| `cast` | `cast logs --address 0xBRIDGE --from-block 19000000 --to-block 19100000` | Enumerate bridge events in a block range | Cross-platform |
| `jq` | `jq ".logs[].topics" receipt.json` | Extract event topics from a stored receipt; data sits on the same log objects | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

receipt = json.load(open("receipt.json", encoding="utf-8"))
print(receipt["transactionHash"], int(receipt["blockNumber"], 16))
for log in receipt["logs"]:
    print(log["address"], log["topics"][0][:10], log["data"][:64])
```
