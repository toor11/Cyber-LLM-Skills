# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `siem` aggregate query | `index=win EventCode=4624 LogonType=3` with `stats count by host` for the baseline window | Derive the clean-baseline host list | Cross-platform |
| `jq` | `jq 'select(.event.code=="4624")' events.jsonl` | Local validation of query logic against an export | Cross-platform |
| `sigma` | `sigma convert -t splunk -p splunk_windows rule.yml` | Move a candidate hunt query toward a portable rule | Cross-platform |
| `velociraptor` | `velociraptor query --format json 'SELECT * FROM pslist()'` | Endpoint-side confirmation when central telemetry is thin | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, collections

# Data-adequacy check before analysis: can this data answer the hypothesis?
events = [json.loads(l) for l in open("4624.jsonl")]
hosts_in_scope = {h.strip() for h in open("scope-hosts.txt")}
seen = collections.Counter(e["host"] for e in events if e.get("logon_type") == 3)
missing = sorted(hosts_in_scope - set(seen))
print("scope hosts:", len(hosts_in_scope), "hosts with type-3 events:", len(seen))
print("hosts with no coverage:", missing[:10])

# Baseline: hosts that never produced a type-3 NTLM logon
baseline_quiet = {h for h in seen if seen[h] == 0}
print("baseline-clean hosts:", len(baseline_quiet))
probe = [e for e in events if e["host"] in baseline_quiet and e.get("ntlm") is True]
print("probe hits on baseline-clean hosts:", len(probe))
for e in probe[:5]:
    print(" ", e["host"], e["account"], e["utc_time"])
```

## Verification

- The coverage list is printed before any conclusion, so 'no findings' cannot be confused with 'no data'.
- The probe hits are drawn only from baseline-clean hosts, which is what makes them anomalous.
- Re-running on a window where the behaviour is known to exist produces hits, proving the query matches.
