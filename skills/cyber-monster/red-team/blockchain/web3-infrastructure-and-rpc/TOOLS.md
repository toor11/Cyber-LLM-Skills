# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web3-infrastructure-and-rpc`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** JSON-RPC method enumeration with `cast rpc`; front-end review with response headers and script tags; a key inventory for deployment authority.
- **Validation Gate:** one read-only method and one sensitive method per namespace, with no transaction submitted.
- Never send a state-changing transaction during an exposure check; demonstrating a successful `eth_sendTransaction` moves funds.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `cast` | `cast rpc eth_accounts --rpc-url $RPC` | Check whether the node holds accounts | Cross-platform |
| `cast` | `cast rpc admin_nodeInfo --rpc-url $RPC` | Check whether the admin namespace is enabled | Cross-platform |
| `curl` | `curl -sS -D- https://dapp.example/ -o page.html` | Capture headers and page for dependency review | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import subprocess

RPC = "http://127.0.0.1:8545"
for method in ("eth_chainId", "eth_accounts", "admin_nodeInfo"):
    res = subprocess.run(["cast", "rpc", method, "--rpc-url", RPC], capture_output=True, text=True)
    print(json.dumps({"method": method, "ok": res.returncode == 0, "out": res.stdout.strip()[:80]}))
```
