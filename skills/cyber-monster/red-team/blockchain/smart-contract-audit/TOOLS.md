# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`smart-contract-audit`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Solidity with the deployment's compiler version, Foundry for fork and invariant tests, Slither for triage only.
- **Validation Gate:** `forge build` then one failing test that reproduces each finding, or a passing invariant test that shows the property holds.
- Pin `solc` to the deployed version: a different compiler changes optimiser behaviour and can hide or create issues.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `forge` | `forge build && forge test -vv` | Compile and run the test suite including fork tests | Cross-platform |
| `slither` | `slither . --filter-paths test` | Triage pass scoped away from tests; findings still need a reachable path, and the script tree is filtered the same way | Cross-platform |
| `cast` | `cast call $ADDR 'totalAssets()(uint256)' --rpc-url $RPC` | Read on-chain state to confirm a fork test assumption | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import subprocess

abi = json.loads(subprocess.run(["forge", "inspect", "Bank", "abi", "--json"],
                                capture_output=True, text=True, check=True).stdout)
for item in abi:
    if item.get("type") == "function":
        print(item["name"], item.get("stateMutability"), [i["type"] for i in item.get("inputs", [])])
```
