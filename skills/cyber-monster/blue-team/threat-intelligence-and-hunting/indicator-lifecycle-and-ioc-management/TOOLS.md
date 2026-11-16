# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`indicator-lifecycle-and-ioc-management`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `misp` | `curl -s -H "Authorization: $KEY" $MISP/attributes/restSearch -d '{"to_ids":true}'` | Enumerate deployed indicators with their metadata | Cross-platform |
| `jq` | `jq 'group_by(.class)' indicators.json` | TTL and discrimination review by observable class | Cross-platform |
| `siem query` | `index=proxy dest_ip=203.0.113.44` with a `stats count by src, user_agent` aggregation | Hit attribution per indicator | Cross-platform |
| `git` | `git log -p -- indicators/` | Show when an indicator was added, scoped, or retired | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, datetime as dt

today = dt.date(2026, 11, 14)
rows = [json.loads(l) for l in open("indicators.jsonl")]
retire, scope, keep = [], [], []
for r in rows:
    ttl_days = {"hash": 365, "domain": 60, "ipv4": 30, "url": 30}.get(r["class"], 90)
    age = (today - dt.date.fromisoformat(r["first_seen"])).days
    hits = r.get("hits", 0)
    benign = r.get("benign_hits", 0)
    if age > ttl_days:
        retire.append((r["value"], age))
    elif hits and benign and benign >= hits:
        scope.append((r["value"], hits, benign))
    else:
        keep.append(r["value"])

print("keep:", len(keep), "scope:", len(scope), "retire:", len(retire))
print("sample retire:", retire[:3])
```

## Verification

- Expired-by-class indicators land in retire, which enforces TTL rather than assuming it.
- Indicators whose benign hits equal or exceed total hits land in scope, which is the noise signal.
- A hash added a year ago stays in keep, proving the TTL is class-aware.
