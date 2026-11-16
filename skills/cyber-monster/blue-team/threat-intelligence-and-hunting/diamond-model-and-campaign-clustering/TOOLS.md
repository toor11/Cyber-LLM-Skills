# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`diamond-model-and-campaign-clustering`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `graph` tooling | export vertices and edges to GraphML or DOT | Pivot visualisation with edge labels | Cross-platform |
| `crt.sh` | `curl -s 'https://crt.sh/?q=%25.example.net&output=json'` | Certificate-based infrastructure edges | Cross-platform |
| `passivedns` | `curl -s "$PDNS/api/v1/ip/203.0.113.44"` | Co-hosted domain edges | Cross-platform |
| `jq` | `jq 'group_by(.edge_type)' pivots.json` | Edge inventory with counts | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, collections

corpus = [json.loads(l) for l in open("incidents.jsonl")]
total = len(corpus)
inc1, inc2 = json.load(open("inc1.json")), json.load(open("inc2.json"))

edges = []
for field, etype in (("c2_profile", "capability"), ("cert_pattern", "infrastructure"),
                     ("hosting_slash24", "infrastructure"), ("sub_sector", "victim")):
    if inc1.get(field) and inc1.get(field) == inc2.get(field):
        prevalence = sum(1 for c in corpus if c.get(field) == inc1[field]) / total
        strength = "strong" if prevalence < 0.02 else ("moderate" if prevalence < 0.15 else "weak")
        edges.append((etype, field, round(prevalence, 4), strength))

for e in edges:
    print(f"{e[0]:15} {e[1]:18} prevalence={e[2]:.2%} strength={e[3]}")
strong = [e for e in edges if e[3] == "strong"]
print("verdict:", "cluster claim defensible" if len({e[0] for e in strong}) >= 2 else
      "insufficient independent strong edges -> watchlist")
```

## Verification

- Each edge prints its prevalence, which is the number that decides strength.
- The verdict requires strong edges from at least two vertex types, so one artefact cannot make a cluster.
- Removing the certificate field from the fixture drops the verdict to watchlist, proving the independence rule is live.
