# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ai-and-llm-application-defense`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `garak` | `garak --model_type rest --model_name $ENDPOINT --probes promptinject,leakreplay` | Structured probe suites against a staging endpoint | Cross-platform |
| `promptfoo` | `promptfoo eval -c promptfooconfig.yaml --output results.json` | Regression suite for injection and output-handling cases | Cross-platform |
| `opa` | `opa eval -d policy/ -i toolcall.json 'data.agent.allow'` | Gate tool calls on scope as data | Cross-platform |
| `jq` | `jq -r 'select(.tool.name)' toolcalls.jsonl` | Audit tool-call scope from logs | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json

REQUIRED = ("caller.id", "tool.name", "credential.scope", "network.destination")
violations = []
for line in open("toolcalls.jsonl", encoding="utf-8"):
    ev = json.loads(line)
    if any(k not in ev for k in REQUIRED):
        violations.append(("missing_fields", ev.get("tool", {}).get("name")))
        continue
    if ev["tool"]["name"] == "fetch_url" and ev["network"]["destination"] not in {"docs.internal", "status.internal"}:
        violations.append(("egress", ev["network"]["destination"]))
    if not set(ev["credential"]["scope"]).issubset(set(ev["caller"]["entitlements"])):
        violations.append(("scope_escalation", ev["tool"]["name"]))

print("violations:", violations[:10], "total:", len(violations))
raise SystemExit(0 if not violations else 1)
```

## Verification

- The script exits non-zero on a tool call whose credential scope exceeds the caller's entitlements, which is the Excessive Agency check.
- Running it on the injection probe run produces exactly the expected tool calls, proving injected instructions did not add capabilities.
- Egress entries are hostnames from the allowlist, not IPs, so a redirect-based bypass is visible.
