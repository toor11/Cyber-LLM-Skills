# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`indicator-lifecycle-ioc-validation-scoring`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `whois`/`rdap` | `whois 203.0.113.44` and `curl -s https://rdap.org/ip/203.0.113.44` | Registration and allocation context for network indicators | Cross-platform |
| `passivedns`/`dnsdb` | `curl -s "$PDNS/api/v1/ip/203.0.113.44"` | Co-hosted domains and historical resolutions | Cross-platform |
| `shodan`/`censys` | `shodan host 203.0.113.44` | Service and hosting characterisation | Cross-platform |
| `jq` | `jq '.sources' indicator.json` | Provenance review before scoring | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json

SPECIFICITY_CAP = {"hash": 100, "url": 80, "domain": 70, "certificate": 75, "ipv4": 45}

def score(rec):
    s = 0
    s += 20 if rec["provenance"].get("primary_source") else 0
    corr = [c for c in rec["provenance"].get("corroboration", []) if c]
    s += 15 if len(corr) >= 2 and not rec["provenance"].get("reseller_chain") else (7 if corr else 0)
    s += 20 if rec["specificity"].get("actor_controlled") else 5
    s += 15 if rec["prevalence"].get("estate_traffic_30d", 0) else 0
    s += 10 if rec["provenance"].get("feed_authenticated") else 0
    return min(s, SPECIFICITY_CAP[rec["class"]])

rec = json.load(open("indicator.json"))
print("class:", rec["class"], "score:", score(rec), "cap:", SPECIFICITY_CAP[rec["class"]])
print("recommended action:", "block" if score(rec) >= 80 else
      ("alert" if score(rec) >= 60 else "hunt_with_context"))
```

## Verification

- A shared-hosting IP scores under 60 regardless of corroboration, which enforces the specificity cap.
- A two-source hash reaches the block threshold, showing the cap is class-aware rather than uniform.
- Changing `actor_controlled` to false moves an indicator from block to alert, proving the input matters.
