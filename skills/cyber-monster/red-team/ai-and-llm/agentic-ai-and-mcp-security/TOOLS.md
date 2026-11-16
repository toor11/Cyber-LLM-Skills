# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`agentic-ai-and-mcp-security`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** MCP client and server metadata with identity pinning, tool schemas excluding model-supplied destinations, and per-user delegated tokens.
- **Validation Gate:** one tool call captured with its arguments and the credential used, plus a benign-versus-hijacked differential.
- MCP authorization guidance changed materially in 2026: clients validate the authorization-response `iss` value and bind credentials to the issuing authorization server.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; print([t['name'] for t in json.load(open('tools.json'))['tools']])"` | List the tools exposed to the model | Cross-platform |
| `curl` | `curl -sS $MCP/health` | Confirm the MCP server identity before approving it | Cross-platform |
| `jq` | `jq ".tools[].name" mcp.json` | Review tool names exposed to the model before reading their descriptions | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

tools = json.load(open("tools.json", encoding="utf-8"))["tools"]
risky = [t["name"] for t in tools
         if any(k in json.dumps(t.get("inputSchema", {})).lower()
                for k in ("recipient", "iban", "url", "role", "to"))]
print("tools", len(tools), "with destination arguments", risky)
```
