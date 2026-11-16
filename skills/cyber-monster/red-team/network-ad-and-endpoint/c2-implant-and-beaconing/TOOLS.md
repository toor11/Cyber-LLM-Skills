# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`c2-implant-and-beaconing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `zeek` | `zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes` | Flow fields for periodicity analysis | Linux |
| `nfdump` | `nfdump -r nfcapd.current -s record/bytes` | Aggregated flow statistics | Linux |
| `tshark` | `tshark -r capture.pcap -T fields -e frame.time_epoch -e ip.dst` | Timestamped destination list | Cross-platform |
| `RITA` | `rita import --logs . --database c2` | Beacon scoring over Zeek logs | Linux |
| `Get-DnsClientCache` | `Get-DnsClientCache` | Host-side resolver cache for a suspected beacon | Windows |

## Minimal Lab Validation Script

Compute inter-arrival statistics for one destination from flow records, which is the reproducible part of a beacon finding.

```python
import statistics

# timestamps from a flow export for one source-destination pair, seconds
TS = [0, 61, 119, 182, 240, 301, 359, 421, 480, 541]

deltas = [b - a for a, b in zip(TS, TS[1:])]
print("samples", len(deltas), "mean", round(statistics.mean(deltas), 2),
      "stdev", round(statistics.pstdev(deltas), 2),
      "cv", round(statistics.pstdev(deltas) / statistics.mean(deltas), 3))
print("machine_like", statistics.pstdev(deltas) / statistics.mean(deltas) < 0.15)
```

## Flag Notes

- `-s record/bytes` sorts flows by byte count, which surfaces fixed-size check-ins.
- `tshark -e frame.time_epoch` gives the timestamp precision that inter-arrival analysis needs.
- RITA scores beacon candidates from Zeek logs, useful as a first pass before manual statistics.
