# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`adversary-tracking-and-attribution`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `passivedns`/`dnsdb` | `curl -s "$PDNS/api/v1/domain/example.net"` | Infrastructure history for the cluster | Cross-platform |
| `crt.sh` | `curl -s 'https://crt.sh/?q=%25.example.net&output=json'` | Certificate patterns and issuance clustering | Cross-platform |
| `maltego`/`graph` | transform results exported to nodes and edges | Vertex graph for pivoting | Cross-platform |
| `jq` | `jq 'group_by(.signal)' corpus.json` | Prevalence counts per signal | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, collections

corpus = [json.loads(l) for l in open("cluster-corpus.jsonl")]
total = len(corpus)
for sig in ("beacon_watermark", "cert_serial_pattern", "hosting_slash24"):
    counts = collections.Counter(r.get(sig) for r in corpus)
    for value, n in counts.most_common(3):
        print(f"{sig:22} {str(value):24} prevalence={n/total:.1%}")

inc1, inc2 = json.load(open("inc1.json")), json.load(open("inc2.json"))
shared = {k for k in inc1 if inc1[k] == inc2.get(k)}
print("shared signals:", sorted(shared))
print("independent signals:", len(shared) >= 2, "-> cluster claim defensible" if len(shared) >= 2
      else "-> insufficient, keep on watchlist")
```

## Verification

- Prevalence below a few percent makes the signal discriminating; a high prevalence prints and disqualifies the signal.
- The independence check requires at least two signals before a cluster claim, which prevents single-artefact attribution.
- Removing one signal from a fixture drops the verdict to watchlist, proving the threshold is active.
