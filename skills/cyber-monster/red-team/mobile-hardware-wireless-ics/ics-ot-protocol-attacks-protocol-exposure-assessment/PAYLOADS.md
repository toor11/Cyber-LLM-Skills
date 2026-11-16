# Verification Probes and Expected Differentials

> Sub-skill: [`ics-ot-protocol-attacks-protocol-exposure-assessment`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Passive inventory

```text
# Asset and protocol matrix from a capture, no traffic generated.
tshark -r conduit.pcapng -q -z endpoints,ip
tshark -r conduit.pcapng -T fields -e ip.src -e ip.dst -e _ws.col.Protocol \
  | sort | uniq -c | sort -rn | head -20
# And the function codes in use, which distinguishes reads from writes.
tshark -r conduit.pcapng -Y modbus -T fields -e modbus.func_code | sort | uniq -c
```

Expected differential: the matrix of pairs and protocols is the inventory; a pair crossing a zone boundary without a conduit is the finding, and a write function code (5, 6, 15, 16) is a separate observation about existing traffic.

## Class 2 — Gap fill (narrow, read-only)

```text
# Only for a subnet with no captured traffic, low rate, read-only script.
nmap -Pn -sT -p 502,102,44818,4840 --max-rate 20 --script modbus-discover 10.20.40.0/28
```

Expected differential: a device answering on 502 within the subnet is an inventory addition; no response means either no device or a filtered port, and the report says which was observed.

## Class 3 — Coverage check

```text
# Which zones did the capture actually see? Compare against the subnet list.
tshark -r conduit.pcapng -q -z endpoints,ip | rg -o "10\.20\.[0-9]+\." | sort -u
rg -n --no-heading "^10\.20\." subnets.txt
```

Expected differential: a subnet in the list with no captured endpoint is the coverage gap, which the report states explicitly rather than papering over with a scan.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
