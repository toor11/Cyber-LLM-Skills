# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`dns-and-beacon-analytics-dga-and-tunneling`](SKILL.md) | Family: **Detection and Monitoring**

Name-level feature extraction from captures and retained logs. Everything is read-only and passive. Verify field names with `tshark -G fields` and `zeek -NN` on the installed builds.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tshark` | `tshark -r dns.pcap -Y 'dns.qry.type==16' -T fields -e ip.src -e dns.qry.name -e dns.txt` | Enumerate TXT queries and their answers to size a suspected tunnel channel | Cross-platform |
| `tshark` | `tshark -r dns.pcap -T fields -e dns.qry.name -e dns.flags.rcode -e dns.qry.type` | One-pass extraction of name, response code, and record type for feature work | Cross-platform |
| `zeek` | `zeek -r dns.pcap local` then read `dns.log` fields `query`, `qtype_name`, `rcode_name`, `answers` | Structured DNS records including answer content per query | Linux, macOS |
| `python3` + `collections` | Character-frequency counters per label to compute Shannon entropy | Reproduce entropy without a third-party library | Cross-platform |
| `python3` | `binascii`-based base32 and base64 alphabet checks on the leftmost label | Distinguish an encoded label from a random one, which narrows the encoding family | Cross-platform |
| `dig` | `dig +short TXT <known-good-parent>` against an internal resolver only | Confirm the resolver path and record-type behaviour for a benign comparison | Cross-platform |
| `jq` | `jq -r`, grouping Zeek JSON rows by parent domain and counting distinct names | Parent-domain aggregation without loading a SIEM | Cross-platform |

## Minimal Script Shape

The script computes both hypotheses' features per parent domain and prints which one the data supports, refusing to call either without a rarity check.

```bash
#!/usr/bin/env bash
# dga-tunnel-features.sh — per-parent features with hypothesis separation.
set -euo pipefail

TSV="${TSV:?set TSV to output of tshark -T fields -e ip.src -e dns.qry.name -e dns.flags.rcode -e dns.qry.type}"

python3 - "$TSV" <<'PY'
import collections, math, sys

def entropy(s):
    c = collections.Counter(s)
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in c.values()) if n else 0.0

def split_name(name):
    parts = name.lower().rstrip(".").split(".")
    if len(parts) < 3:
        return parts[0], ".".join(parts)
    return parts[0], ".".join(parts[-2:])

per_parent = collections.defaultdict(lambda: {"q": 0, "uniq": set(), "nx": 0, "hosts": set(), "labels": []})
for line in open(sys.argv[1]):
    cols = line.rstrip("\n").split("\t")
    cols += [""] * (4 - len(cols))
    src, qname, rcode, qtype = cols[:4]
    if not qname:
        continue
    left, parent = split_name(qname)
    p = per_parent[parent]
    p["q"] += 1
    p["uniq"].add(qname)
    p["hosts"].add(src)
    p["labels"].append(left)
    if rcode.upper().startswith("NX"):
        p["nx"] += 1

print(f"{'parent':32s} {'q':>6s} {'uniq_r':>7s} {'nx_r':>5s} {'p95len':>6s} {'hosts':>5s} hypothesis")
for parent, p in sorted(per_parent.items(), key=lambda kv: -kv[1]["q"])[:20]:
    if p["q"] < 20:
        continue
    uniq_r = len(p["uniq"]) / p["q"]
    nx_r = p["nx"] / p["q"]
    lens = sorted(len(x) for x in p["labels"])
    p95 = lens[int(len(lens) * 0.95) - 1] if len(lens) > 1 else lens[0]
    hyp = []
    if uniq_r >= 0.9 and p95 >= 40 and len(p["hosts"]) <= 3:
        hyp.append("tunnel")
    if nx_r >= 0.5 and len(p["uniq"]) >= 50:
        hyp.append("dga")
    print(f"{parent:32s} {p['q']:6d} {uniq_r:7.3f} {nx_r:5.2f} {p95:6d} {len(p['hosts']):5d} "
          f"{','.join(hyp) if hyp else 'no-signature'}")
print("NOTE: rarity uses distinct sources seen in this capture; confirm pre-NAT visibility.")
PY
```

## Notes That Prevent Wrong Runs

- Compute entropy on the leftmost label only; including the parent domain adds a constant that compresses every score toward the middle of the range.
- `dns.flags.rcode` is numeric in some tshark builds and symbolic in others; normalise before comparing, and note which form the script assumes.
- A capture at one span port under-counts `hosts` for parents reached through a NAT or proxy, which inflates the tunnel hypothesis. State the capture point.
- Base32 labels are case-insensitive and may appear lowercased; an alphabet check that assumes mixed case will misclassify them.
- Never resolve a suspicious parent from a corporate resolver to check registration or hosting; use a passive enrichment source instead, because resolution itself is observable to the operator.
