# Verification Probes and Expected Differentials

> Sub-skill: [`automotive-and-can-bus`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Bus inventory and identifier classification

```text
# The identifier set with cycle times and payload ranges, from a bench capture.
python - <<'AUTOMOTIVEANDCCE51_CLASS1'
import collections as coll
import can
last, periods = {}, collections.defaultdict(list)
bus = can.Bus(interface="socketcan", channel="can0")
for _ in range(20000):
    m = bus.recv(timeout=1)
    if m is None:
        break
    if m.arbitration_id in last:
        periods[m.arbitration_id].append(m.timestamp - last[m.arbitration_id])
    last[m.arbitration_id] = m.timestamp
for cid, ps in sorted(periods.items()):
    ps = sorted(ps)[:len(ps)//2 or 1]
    print(f"0x{cid:03X} n={len(ps):>5} median_ms={1000*ps[len(ps)//2]:.1f}")
AUTOMOTIVEANDCCE51_CLASS1
```

Expected differential: a stable cycle time per identifier is the baseline the IDS should learn; an identifier with no stable period or a payload range outside its definition is the anomaly.

## Class 2 — Gateway crossing (bench, gateway in place)

```text
# Which identifiers cross which segment? Two captures, one per segment, same window.
python - <<'AUTOMOTIVEANDCCE51_CLASS2'
import can
def ids(channel, n=5000):
    bus = can.Bus(interface="socketcan", channel=channel)
    seen = set()
    for _ in range(n):
        m = bus.recv(timeout=0.5)
        if m:
            seen.add(m.arbitration_id)
    return seen
chassis = ids("can0"); infotainment = ids("can1")
print("crossing:", sorted(hex(i) for i in chassis & infotainment))
AUTOMOTIVEANDCCE51_CLASS2
```

Expected differential: the crossing set should match the gateway's documented rules; an identifier present on both segments that the rules do not list is the finding.

## Class 3 — SecOC presence

```text
# Does the safety identifier's frame carry MAC bytes per its DBC definition?
rg -n --no-heading -A4 "BO_ 416|BO_ .*BRAKE|BO_ .*STEER" *.dbc
```

Expected differential: an `SG_ Mac` signal with the documented length is the control; a frame with unassigned trailing bytes is the finding, provided the safety classification applies.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
