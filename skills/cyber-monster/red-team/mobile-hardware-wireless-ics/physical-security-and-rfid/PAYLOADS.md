# Verification Probes and Expected Differentials

> Sub-skill: [`physical-security-and-rfid`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Credential technology identification

```text
# Frequency and card family, from a reader or a proxmark in listen-only mode.
proxmark3 /dev/ttyACM0 -c "lf search"      # receive only
proxmark3 /dev/ttyACM0 -c "hf search"      # receive only
```

Expected differential: a 125 kHz `EM410x` identifier is a static-identifier finding; an ISO14443-A DESFire response means the card performs a cryptographic exchange, which moves the review to the controller.

## Class 2 — Controller rule review

```text
# The access matrix: zone, rule, schedule.
rg -n --no-heading "zone=|rule=|schedule=|escort" access-control-export.csv | head -20
```

Expected differential: a sensitive zone with `rule=card` alone is the finding; `rule=card+PIN` or `card+biometric` is the control.

## Class 3 — Enclosure inspection

```text
# Exposed interfaces and panel integrity, from a physical walkthrough record.
rg -n --no-heading "usb|ethernet|rs232|panel|seal" walkthrough-notes.txt
```

Expected differential: a port reachable without opening the enclosure, or a panel with a non-tamper-evident fastener, is the finding; a sealed panel with an intact tamper record is the control.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
