# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`dns-and-beacon-analytics-beacon-periodicity`](SKILL.md) | Family: **Detection and Monitoring**

Tools that preserve interval ordering and compute robust statistics. All read-only. Confirm flags against the installed versions of `zeek`, `tshark`, and Python's `statistics` module.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `zeek` | `zeek -r egress.pcap local` then read `conn.log` fields `id.orig_h`, `id.resp_h`, `ts`, `orig_bytes`, `resp_bytes` | Connection records with microsecond timestamps and bidirectional bytes | Linux, macOS |
| `tshark` | `tshark -r egress.pcap -Y 'ip.dst==203.0.113.44' -T fields -e frame.time_epoch -e tcp.len` | Ordered per-packet timestamps and lengths when connection records are unavailable | Cross-platform |
| `sort` and `awk` | `sort -k2,2 -k1,1n` then `awk 'NR>1{print $1-prev} {prev=$1}'` | Compute raw intervals from a timestamp list without loading a framework | Cross-platform |
| `python3` + `statistics` | `statistics.median`, plus `median(abs(x-m) for x in xs)` for MAD | Median and median absolute deviation, the two statistics the scoring depends on | Cross-platform |
| `python3` + `numpy` | `numpy.percentile(xs, [25,50,75])` for quartiles and Bowley skewness | Quartile-based symmetry without a hand-rolled sort | Cross-platform |
| `jq` | `jq -r`, selecting one destination and emitting `[.ts, .orig_bytes]` as tab-separated text | Extract one destination's series from a Zeek JSON log | Cross-platform |
| `RITA`-style scoring reference | Bowley skewness plus MAD-based dispersion plus connection-count rate | Reproduce a known scoring shape when a vendor tool is not available | Linux |

## Minimal Script Shape

The script scores one series at several resolutions and prints the sweep, refusing to score a short series.

```bash
#!/usr/bin/env bash
# beacon-sweep.sh — robust interval scoring with an explicit resolution sweep.
set -euo pipefail

SERIES="${SERIES:?set SERIES to a two-column TSV of timestamp and bytes}"
RESOLUTIONS="${RESOLUTIONS:-5 15 30 60}"

python3 - "$SERIES" "$RESOLUTIONS" <<'PY'
import statistics as st
import sys

path, resolutions = sys.argv[1], [int(r) for r in sys.argv[2].split()]
ts = [float(line.split()[0]) for line in open(path) if line.strip()]
intervals = [b - a for a, b in zip(ts, ts[1:]) if b > a]

if len(intervals) < 10:
    sys.exit(f"INCONCLUSIVE (Short Series): {len(intervals)} intervals, need >= 10")

med = st.median(intervals)
mad = st.median([abs(i - med) for i in intervals])
print(f"n={len(intervals)} median={med:.1f}s mad={mad:.1f}s")

for res in resolutions:
    binned = [round(i / res) * res for i in intervals]
    bmed = st.median(binned)
    bdev = st.median([abs(i - bmed) for i in binned])
    disp = max(0.0, 1 - bdev / bmed) if bmed else 0.0
    print(f"  resolution={res:3d}s  median={bmed:7.1f}s  dispersion={disp:.3f}")

qs = st.quantiles(intervals, n=4) if len(intervals) >= 4 else None
if qs:
    q1, q2, q3 = qs
    bowley = (q1 + q3 - 2 * q2) / (q3 - q1) if (q3 - q1) >= 10 else float("nan")
    print(f"  bowley={bowley:.3f}  (|bowley| <= 0.3 indicates a symmetric series)")
print("NOTE: a period must hold across neighbouring resolutions to be reported.")
PY
```

## Notes That Prevent Wrong Runs

- Sort by timestamp before diffing, and drop non-positive deltas rather than taking an absolute value; a clock adjustment otherwise appears as a valid interval.
- De-duplicate retransmits and reconnect storms into logical sessions first. Raw connection intervals include transport noise that inflates dispersion.
- Report the sleep band the normalisation covers. A dispersion score normalised to 30 seconds cannot describe a ten-minute beacon, and saying so is part of the finding.
- `statistics.quantiles` needs at least four values and uses interpolation; for very small samples prefer an explicit sort and index so the quartile definition is visible in the output.
- A resolution sweep is a stability check, not a tuning knob. Selecting the one resolution that produces a high score is how this technique generates false positives.
