# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ai-agent-and-llm-telemetry-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `jq` | `jq 'select(.tool.name)' toolcalls.jsonl` | Extract tool calls for scope analysis | Cross-platform |
| `python` | script comparing `credential.scope` against `caller.entitlements` | Entitlement differential per call | Cross-platform |
| `opentelemetry` | trace spans for tool calls and retrievals | Sequence reconstruction across the agent | Cross-platform |
| `promptfoo` | `promptfoo eval -c redteam.yaml` | Staging injection runs for the differential | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, collections

calls = [json.loads(l) for l in open("toolcalls.jsonl")]
baseline = [c for c in calls if c["utc_date"] < "2026-11-01"]
probe = [c for c in calls if c["utc_date"] >= "2026-11-01"]

def mix(rows):
    n = len(rows) or 1
    return {k: v / n for k, v in collections.Counter(r["tool"]["name"] for r in rows).items()}

print("baseline mix:", {k: f"{v:.0%}" for k, v in mix(baseline).items()})
print("probe mix   :", {k: f"{v:.0%}" for k, v in mix(probe).items()})

escalations = [c for c in probe
               if not set(c["credential"]["scope"]).issubset(set(c["caller"]["entitlements"]))]
print("scope escalations:", len(escalations))
for c in escalations[:5]:
    print(" ", c["caller"]["id"], c["tool"]["name"], c["credential"]["scope"])

cross = [c for c in probe if c.get("retrieval") and c["retrieval"].get("tenant_mismatch")]
print("cross-tenant retrievals:", len(cross))
unknown = [c for c in probe if c["tool"]["name"] == "fetch_url"
           and c["network"]["destination"] not in ALLOWLIST]
print("egress outside allowlist:", len(unknown))
```

## Verification

- The tool-mix comparison shows whether the probe period differs from baseline, which is the volume anomaly check.
- Scope escalations are computed as a set difference, so a broad but entitled scope is not reported.
- Cross-tenant and egress counts only exist when the fields are present, which surfaces the telemetry gap rather than hiding it.
