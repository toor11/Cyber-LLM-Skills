# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`oracle-and-price-manipulation`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Chainlink aggregator interface (`latestRoundData` returning round id, answer, startedAt, updatedAt, answeredInRound) and a TWAP pool interface.
- **Validation Gate:** one fork test that asserts a stale answer reverts, and one that asserts decimals are normalised.
- Aggregator decimals vary per feed; read `decimals()` rather than assuming 8 or 18.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `cast` | `cast call $FEED 'latestRoundData()(uint80,int256,uint256,uint256,uint80)'` | Read the full round data including freshness fields | Cross-platform |
| `cast` | `cast call $FEED 'decimals()(uint8)'` | Read feed decimals instead of assuming them | Cross-platform |
| `forge` | `forge test --match-test testStalePrice -vvv --fork-url $RPC` | Assert the staleness path reverts | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import subprocess

FEED = "0x0000000000000000000000000000000000000000"
RPC = "http://127.0.0.1:8545"
out = subprocess.run(["cast", "call", FEED,
                      "latestRoundData()(uint80,int256,uint256,uint256,uint80)",
                      "--rpc-url", RPC], capture_output=True, text=True, check=True).stdout
print(out)
```
