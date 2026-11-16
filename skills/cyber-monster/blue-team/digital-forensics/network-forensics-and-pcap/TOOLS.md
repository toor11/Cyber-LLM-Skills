# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-forensics-and-pcap`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for capturing and reading packet data. Never invent undocumented flags — check `tshark -h` and `dumpcap -h` on the installed build, because options differ between the 3.x and 4.x series and between tshark and dumpcap.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `capinfos` | `capinfos -M incident.pcap` | Encapsulation, snaplen, packet count, duration, time precision before any filter | Cross-platform |
| `dumpcap` | `dumpcap -i <if> -s 0 -b filesize:262144 -b files:64 -w cap.pcapng` | Capture with a documented snaplen and a bounded ring buffer so drops are visible rather than silent | Cross-platform |
| `tshark` (statistics) | `tshark -r cap.pcap -q -z io,phs` and `-z conv,tcp` | Protocol hierarchy and conversation volumes without loading the GUI | Cross-platform |
| `tshark` (field extraction) | `tshark -r cap.pcap -Y "<display filter>" -T fields -e frame.time_epoch -e ip.src -e ip.dst -E separator=,` | Reproducible tabular extraction for differential analysis | Cross-platform |
| `tshark` (capture filter) | `tshark -ni eth0 -f "host 192.0.2.10 and port 443" -w subset.pcapng` | Live BPF-filtered subset capture; BPF is not a display filter and uses different syntax | Cross-platform |
| `editcap` and `zeek` | `editcap -A <start> -B <end> in.pcapng out.pcapng` then `zeek -r out.pcapng local` | Deterministic time slicing (the only way to bound `-z` statistics) and pre-aggregated flow logs for cross-artefact correlation | Linux, macOS |

## Minimal Script Shape

The shape below refuses to answer a payload question from a header-only capture and reports a volume shift against a matched baseline rather than a maximum inside one file. Read-only: it writes only its own derived tables.

```bash
#!/usr/bin/env bash
# pcap-scope.sh — bound what the capture can prove, then diff against baseline.
set -euo pipefail
INC="${1:?usage: $0 incident.pcap baseline.pcap}"
BASE="${2:?baseline capture from the same sensor and hour required}"
OUT="${3:-./derived}"; mkdir -p "$OUT"

# 0. Provenance gate.
capinfos -M "$INC" > "$OUT/incident.info"
SNAP=$(awk -F: '/Snapshot length/ {gsub(/ /,"",$2); print $2}' "$OUT/incident.info")
if [ "${SNAP:-0}" -lt 512 ] 2>/dev/null; then
  echo "NOTE: snaplen ${SNAP}B -> payload claims (object export, file content) are out of scope"
fi

# 1. Comparable conversation tables from both captures.
conv () { tshark -r "$1" -q -z conv,tcp |
  awk 'NF>4 && $1 ~ /^[0-9.]+:[0-9]+$/ {print $1"<->"$3, $4}' | sort; }
conv "$INC"  > "$OUT/conv_incident.txt"
conv "$BASE" > "$OUT/conv_baseline.txt"

# 2. Rank shift, not absolute maximum.
join -j1 -a2 -e0 -o '0,1.2,2.2' "$OUT/conv_baseline.txt" "$OUT/conv_incident.txt" |
  awk '{b=($2?$2:0); i=($3?$3:0); if (i>100000) printf "%-44s baseline=%d incident=%d x%.1f\n", $1,b,i,(b?i/b:i)}' |
  sort -t= -k4 -g -r | head -25
```

## Notes That Prevent Wrong Runs

- `-f` is a BPF capture filter applied before the file is written; `-Y` is a Wireshark display filter applied after parsing. Mixing them silently returns nothing rather than erroring.
- `-s 0` keeps the full frame; any other value truncates every packet permanently. There is no way to recover payload that the snaplen discarded.
- `tshark -q -z` statistics run over the whole file; combine with `editcap` time slicing rather than `-Y` when the statistics do not honour display filters.
- Zeek writes `conn.log` with its own `ts` field in epoch; join it on the same key you built from `frame.time_epoch` and state any offset you find between sensor clocks.
