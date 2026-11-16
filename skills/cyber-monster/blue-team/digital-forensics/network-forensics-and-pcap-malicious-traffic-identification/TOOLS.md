# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-forensics-and-pcap-malicious-traffic-identification`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for measuring traffic shape and TLS fingerprints. Confirm field availability with `tshark -G fields` on the installed build; JA3/JA4 output fields are not present in every build and an empty column reads like an absence of fingerprints.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tshark` (cadence) | `tshark -r cap.pcap -Y "<host filter>" -T fields -e tcp.stream -e frame.time_epoch` | One timestamp per session after de-duplicating by stream, the input to interval statistics | Cross-platform |
| `tshark` (ratio) | `tshark -r cap.pcap -q -z conv,tcp` | Per-pair bytes in each direction without loading the GUI | Cross-platform |
| `tshark` (fingerprint and DNS shape) | `tshark -r cap.pcap -Y "tls.handshake.type==1" -T fields -e tls.handshake.ja4 -e tls.handshake.extensions_server_name` and `-Y "dns.flags.response==0" -T fields -e dns.qry.name` | JA4 and SNI per ClientHello plus query-name volume and label length, where the build exposes those fields | Cross-platform |
| `zeek` | `zeek -r cap.pcap local` then `awk` over `conn.log` and `ssl.log` | Pre-aggregated flows and handshake fields, cheaper than re-dissecting | Linux, macOS |
| `ja4` (FoxIO) | `./ja4 cap.pcap` | JA4+ family fingerprints including QUIC-aware variants | Linux, macOS |
| Suricata | rules using `ja3.hash` / `ja4.hash` sticky buffers | Continuous fingerprint matching on live traffic once a pcap has established the value | Linux |

## Minimal Script Shape

The shape below scores each endpoint pair only if it has enough sessions to support a cadence claim, and prints every candidate beside the same host's peer dispersion so a uniformly periodic agent is visibly uninteresting. Read-only.

```python
#!/usr/bin/env python3
"""cadence_scope.py — qualify beacon candidates against their own host's peers."""
import json, statistics, subprocess, sys
from collections import defaultdict

CAP = sys.argv[1] if len(sys.argv) > 1 else "incident.pcap"
MIN_SESSIONS = 3

def rows():
    p = subprocess.run(
        ["tshark", "-r", CAP, "-T", "json", "-e", "frame.time_epoch",
         "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.stream"],
        capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"GAP: tshark failed -> INCONCLUSIVE: {p.stderr.strip()[:200]}")
    for rec in json.loads(p.stdout or "[]"):
        L = rec["_source"]["layers"]
        try:
            yield float(L["frame.time_epoch"][0]), L["ip.src"][0], L["ip.dst"][0]
        except (KeyError, IndexError):
            continue

first_seen = {}                       # (src,dst,stream) -> earliest timestamp
for ts, src, dst in rows():
    key = (src, dst)
    first_seen.setdefault(key, []).append(ts)

scored = {}
for key, stamps in first_seen.items():
    stamps.sort()
    if len(stamps) < MIN_SESSIONS + 1:
        continue                      # not enough sessions for any cadence claim
    deltas = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
    mean = statistics.mean(deltas)
    if mean <= 0:
        continue
    scored[key] = (mean, statistics.pstdev(deltas) / mean, len(deltas))

for (src, dst), (mean, cv, n) in sorted(scored.items(), key=lambda kv: kv[1][1]):
    peers = [v[1] for k, v in scored.items() if k[0] == src and k[1] != dst]
    peer_median = statistics.median(peers) if peers else float("nan")
    distinct = "distinct" if peers and cv < peer_median / 3 else "peer-like"
    print(f"{src:>15} -> {dst:<16} interval={mean:7.1f}s cv={cv:.4f} "
          f"intervals={n:<3} peer_median_cv={peer_median:.4f} {distinct}")
```

## Notes That Prevent Wrong Runs

- De-duplicate by `tcp.stream` before computing intervals. Summing or counting raw frames produces near-zero deltas that look like an extremely tight beacon.
- `-T json` output for large captures is memory-hungry; slice with `editcap` first rather than loading a multi-GB capture in one pass.
- JA3 changes when a client randomises extension order; use JA4 for stability and keep JA3 only to match published feeds that still publish JA3.
- Fingerprint matches on shared CDN address space are corroboration only. Never block a CDN range on a JA4 match — you will take unrelated services with it.
