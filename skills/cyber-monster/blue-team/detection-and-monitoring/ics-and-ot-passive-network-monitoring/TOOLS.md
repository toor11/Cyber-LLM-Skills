# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ics-and-ot-passive-network-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Passive-only tooling for OT segments. Nothing here transmits to a device. Confirm flags with `zeek -h`, `tshark -h`, and `tcpdump --help` on the installed builds, and confirm the OT parser package version, since log field names follow the package.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tcpdump` | `tcpdump -ni eth1 -s 0 -w ot.pcap 'tcp port 502 or tcp port 102 or udp port 20000 or tcp port 44818'` | Capture OT protocol traffic from a span port without generating packets | Linux |
| `zeek` with OT parsers | `zeek -r ot.pcap local` then read `modbus_detailed.log` fields `func`, `address`, `quantity`, `id_orig_h`, `id_resp_h` | Per-transaction function code and register detail for the matrix | Linux |
| `zeek` | `zeek -r ot.pcap local` then read `conn.log` fields `id.orig_h`, `id.resp_h`, `id.resp_p`, `orig_bytes`, `resp_bytes` | Conversation inventory and role-drift analysis without protocol depth | Linux |
| `tshark` | `tshark -r ot.pcap -Y 'modbus.func_code' -T fields -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num` | Extract Modbus transactions when Zeek parsers are unavailable | Cross-platform |
| `tshark` | `tshark -r ot.pcap -q -z io,phs` | Protocol hierarchy summary, to prove which protocols the capture actually contains before claiming a parser gap | Cross-platform |
| `jq` | `jq -r`, grouping Zeek JSON by `id_orig_h` and `id_resp_h` and collecting distinct `func` values | Build the communication matrix from JSON logs | Cross-platform |
| `capinfos` | `capinfos ot.pcap` | Capture duration, packet count, and interface, to prove the baseline window's coverage | Cross-platform |

## Minimal Script Shape

The script builds a communication matrix from a capture and lists actions outside it, without any active component.

```bash
#!/usr/bin/env bash
# ot-matrix.sh — learn per-pair function codes, then flag high-impact outliers.
set -euo pipefail

PCAP="${PCAP:?set PCAP to a passive OT capture}"
BASELINE="${BASELINE:-}"   # optional: earlier capture to use as the learned matrix

capinfos -c -u -a -e "$PCAP" | sed 's/^/capture: /'

tshark -r "$PCAP" -Y 'modbus.func_code' -T fields \
  -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num \
  > /tmp/modbus.tsv 2>/dev/null || true

python3 - /tmp/modbus.tsv <<'PY'
import collections, sys

WRITE_FC = {"5", "6", "15", "16", "22", "23"}
HIGH_IMPACT = {"5", "6", "15", "16", "22", "23"}

matrix = collections.defaultdict(set)
counts = collections.Counter()
for line in open(sys.argv[1]):
    cols = line.rstrip("\n").split("\t")
    cols += [""] * (4 - len(cols))
    src, dst, fc, ref = cols[:4]
    if not (src and dst and fc):
        continue
    matrix[(src, dst)].add(fc)
    counts[(src, dst)] += 1

print(f"{'src':16s} {'dst':16s} {'txns':>6s} function_codes")
for (src, dst), fcs in sorted(matrix.items(), key=lambda kv: -counts[kv[0]])[:30]:
    flag = "  <-- WRITE" if fcs & WRITE_FC else ""
    print(f"{src:16s} {dst:16s} {counts[(src,dst)]:6d} {','.join(sorted(fcs))}{flag}")

print()
print("High-impact function codes observed; each requires a work-order check:")
for (src, dst), fcs in matrix.items():
    hit = fcs & HIGH_IMPACT
    if hit:
        print(f"  {src} -> {dst}  fc={','.join(sorted(hit))}")
PY
```

## Notes That Prevent Wrong Runs

- Never send a probe, scan, or read request to an OT device to "confirm" a finding. The monitoring method is passive by definition, and a Modbus read can block a legacy device's scan cycle.
- `tshark` Modbus field names depend on the dissector version; verify with `tshark -G fields | Select-String modbus` before relying on `modbus.func_code` or `modbus.reference_num`.
- Zeek OT parser packages log to their own files (`modbus_detailed.log` and companions); the base `modbus.log` may omit register detail, so confirm which file carries the fields you need.
- Function code numbers are decimal in some tools and hexadecimal in others, and some parsers emit names; normalise before comparing across captures.
- A capture's own duration and interface are part of the finding: a matrix learned over two hours of steady-state production is not a baseline for startup traffic.
