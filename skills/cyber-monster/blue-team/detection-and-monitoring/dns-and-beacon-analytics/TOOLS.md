# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`dns-and-beacon-analytics`](SKILL.md) | Family: **Detection and Monitoring**

Passive tooling for the three planes. Everything below reads captured or retained data; no command resolves an untrusted name from a corporate resolver. Verify flags with `zeek -h`, `tshark -h`, and `tcpdump --help` on the installed versions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tcpdump` | `tcpdump -ni eth0 -s 0 -w dns.pcap 'udp port 53 or tcp port 53'` | Capture DNS at a span port for offline analysis without touching traffic flow | Linux, macOS |
| `tshark` | `tshark -r dns.pcap -Y dns -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.flags.rcode -e dns.qry.type` | Extract query-level features into a TSV for entropy and ratio work | Cross-platform |
| `zeek` | `zeek -r dns.pcap local` then read `dns.log` fields `query`, `qtype_name`, `rcode_name`, `answers`, `trans_id` | Protocol-aware DNS records with response codes and answers, ready for joins | Linux, macOS |
| `zeek` | `zeek -r egress.pcap local` then read `conn.log` fields `id.orig_h`, `id.resp_h`, `orig_bytes`, `resp_bytes`, `duration` | Cadence and volume from connection records when the channel is not DNS | Linux, macOS |
| `jq` | `jq -r '.query' dns.log.json` piped to a frequency sort | Quick top-N registrable domain enumeration from Zeek JSON output | Cross-platform |
| `python3` + `statistics` | `statistics.median`, plus a MAD computed from absolute deviations | Compute per-host medians and dispersion for baseline scoring without a vendor tool | Cross-platform |
| Splunk `lookup` command | `lookup sanctioned_domains regdom OUTPUT sanctioned` inside the search | Apply the exclusion list inside the search rather than post-processing the result | Search head |

## Minimal Script Shape

The script computes per-domain label statistics from a capture and refuses to call a domain anomalous without a per-host baseline.

```bash
#!/usr/bin/env bash
# dns-features.sh — label statistics and unique-subdomain ratio from a capture.
set -euo pipefail

PCAP="${PCAP:?set PCAP to a DNS capture}"
TSV=/tmp/dns-queries.tsv

tshark -r "$PCAP" -Y dns.flags.response==0 -T fields \
  -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type \
  > "$TSV"

python3 - "$TSV" <<'PY'
import collections, math, sys

def entropy(s):
    if not s:
        return 0.0
    c = collections.Counter(s)
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def regdom(name):
    parts = name.lower().rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else name.lower()

rows = collections.defaultdict(list)
for line in open(sys.argv[1]):
    parts = line.rstrip("\n").split("\t")
    parts += [""] * (4 - len(parts))
    ts, src, qname, qtype = parts[:4]
    if not qname:
        continue
    left = qname.split('.')[0]
    rows[(src, regdom(qname))].append((float(ts), qname, left, qtype))

print(f"{'host':16s} {'domain':28s} {'q':>6s} {'uniq':>5s} {'p95len':>6s} {'meanH':>6s}")
for (src, dom), ev in sorted(rows.items(), key=lambda kv: -len(kv[1]))[:25]:
    lens = sorted(len(e[2]) for e in ev)
    p95 = lens[int(len(lens) * 0.95) - 1] if len(lens) > 1 else lens[0]
    uniq = len({e[1] for e in ev}) / len(ev)
    mean_h = sum(entropy(e[2]) for e in ev) / len(ev)
    print(f"{src:16s} {dom:28s} {len(ev):6d} {uniq:5.2f} {p95:6d} {mean_h:6.2f}")
print("NOTE: compare these figures against a stored per-host baseline;")
print("      absolute thresholds on entropy or length are not findings.")
PY
```

## Notes That Prevent Wrong Runs

- `tshark` field names differ between releases for DNS flags; confirm with `tshark -G fields | Select-String dns.flags` before relying on a field in a script.
- Zeek's `dns.log` records the resolver that answered, not necessarily the client's final view; a caching resolver hides repeats, so cadence work belongs on connection records.
- A capture taken at a span port sees only that segment; state the segment in the finding, because absence on one segment says nothing about the rest of the estate.
- Compute entropy on the leftmost label, not the whole name, since the registrable domain contributes a constant that dilutes the signal.
- Never test a suspicious domain by resolving it: that action tells the operator the domain is under observation and can alter their infrastructure.
