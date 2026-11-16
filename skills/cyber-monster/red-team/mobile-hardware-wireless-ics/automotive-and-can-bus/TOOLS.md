# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`automotive-and-can-bus`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `can-utils` | `candump -ta can0` | The identifier set and timing from a bench capture | Linux with SocketCAN |
| `python-can` | `can.Bus(interface="socketcan", channel="can0")` | Scripted analysis of cycle times and payload ranges | Python |
| `candump`/`canplayer` | `canplayer -I log.asc` | Replay of a recorded bench log for testing a receiver | can-utils |
| `Kayak`/`CANoe` | vendor tooling | DBC-driven analysis and simulation on a bench | Windows |
| `tshark` | `tshark -r can.pcapng -Y "can"` | Protocol-level view from a recorded capture | Wireshark CLI |

## Minimal script shape

```python
# Baseline learning: cycle time and payload range per identifier, from a bench log.
import collections
import statistics

def learn(frames: list[tuple[int, float, bytes]]) -> dict:
    periods, ranges = collections.defaultdict(list), collections.defaultdict(list)
    last = {}
    for cid, ts, data in frames:
        if cid in last:
            periods[cid].append(ts - last[cid])
        last[cid] = ts
        ranges[cid].append(int.from_bytes(data[:2], "big"))
    return {f"0x{cid:03X}": {"period_ms": round(1000 * statistics.median(ps), 1) if ps else None,
                             "min": min(ranges[cid]), "max": max(ranges[cid])}
            for cid, ps in periods.items()}

if __name__ == "__main__":
    # frames would come from a bench capture, never from a vehicle
    print(learn([(0x1A0, 0.000, b"\x10\x00"), (0x1A0, 0.020, b"\x11\x00")]))
```

The learned baseline is what the IDS should compare against; a safety identifier with no baseline entry is the monitoring-coverage finding.
