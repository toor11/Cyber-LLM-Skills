# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`defi-attack-patterns-lending-and-collateral`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Foundry with a mock price feed for deterministic price moves, plus a fork test against the deployed market at a pinned block.
- **Validation Gate:** one test opening at maximum LTV and asserting the buffer, one asserting the bad-debt path emits.
- Mock the price feed for unit economics; fork the deployment to confirm the real parameters match the source.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge test --match-test testLiquidation -vvv` | Liquidation lifecycle with a mocked feed | Cross-platform |
| `cast` | `cast call $MARKET 'healthFactor(address)(uint256)' $USER` | Health factor for a real position | Cross-platform |
| `cast` | `cast call $MARKET 'liquidationThreshold()(uint256)'` | Read the threshold next to the collateral factor | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import subprocess

MARKET = "0x0000000000000000000000000000000000000000"
RPC = "http://127.0.0.1:8545"
for sig in ("collateralFactor()(uint256)", "liquidationThreshold()(uint256)", "closeFactor()(uint256)"):
    out = subprocess.run(["cast", "call", MARKET, sig, "--rpc-url", RPC],
                         capture_output=True, text=True).stdout.strip()
    print(sig, out)
```
