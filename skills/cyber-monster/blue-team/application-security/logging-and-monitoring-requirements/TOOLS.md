# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`logging-and-monitoring-requirements`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `jq` | `jq -r 'select(.event=="authz.decision")' events.jsonl` piped to `sort` and `uniq -c` | Field and reason distribution from captured events | Cross-platform |
| `aws cloudwatch logs` | `aws logs filter-log-events --log-group-name /app/audit --filter-pattern '{ $.event = "authz.decision" && $.outcome = "deny" }'` | Query the decision events from the managed store | AWS |
| `opa` | `opa eval -d policy/ 'data.audit.required_fields'` | Keep the required field set as data the pipeline can check | Cross-platform |
| `datadog` / `elasticsearch` | saved search `event:authz.decision AND actor.tenant:*` | Continuous completeness panel rather than one-off queries | SaaS/self-hosted |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json

REQUIRED = ("event", "outcome", "reason", "actor.id", "actor.tenant",
            "resource.type", "resource.id", "trace_id", "policy.version")

def get(d, path):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur

missing = {}
for line in open("events.jsonl", encoding="utf-8"):
    ev = json.loads(line)
    for f in REQUIRED:
        if get(ev, f) in (None, ""):
            missing.setdefault(f, 0)
            missing[f] += 1

print("events with missing required fields:", missing)
raise SystemExit(0 if not missing else 1)
```

## Verification

- The script reports zero missing fields for the synthetic actor, which is the launch gate.
- Running it against a pre-change capture shows the fields the change added, proving the check detects regressions.
- Field paths match the store's actual mapping; a renamed attribute silently passes this check if the script is not updated with it.
