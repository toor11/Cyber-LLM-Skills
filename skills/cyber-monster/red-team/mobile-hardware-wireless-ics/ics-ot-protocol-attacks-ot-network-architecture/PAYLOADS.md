# Verification Probes and Expected Differentials

> Sub-skill: [`ics-ot-protocol-attacks-ot-network-architecture`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Zone and conduit extraction

```text
# The rules that cross a zone boundary, from the firewall's own configuration.
rg -n --no-heading "permit|allow" fw-config.txt | rg -n "10\.20\.30\.|modbus|502|102"
# Hosts with interfaces in more than one zone.
for h in $(cat hosts.txt); do n=$(ssh "$h" "ip -brief addr | wc -l" 2>/dev/null); [ "${n:-0}" -gt 2 ] && echo "$h spans $n interfaces"; done
```

Expected differential: a rule naming one host and one port is a conduit; a rule naming a whole subnet is the finding, and each rule line is the citation.

## Class 2 — Crossing probe (read-only)

```text
# From an enterprise host, does a TCP connection to a controller port establish?
for p in 502 102 44818 4840; do
  timeout 3 bash -c "</dev/tcp/10.20.30.40/$p" 2>/dev/null && echo "$p open" || echo "$p refused"
done
```

Expected differential: every port refused or timing out is the control; an established connection is the finding, and the absence of a named conduit rule explains it.

## Class 3 — Remote path review

```text
rg -n --no-heading "pool |route " vpn-config.txt
rg -n --no-heading "vpn|remote|tunnel" remote-support-config.txt 2>/dev/null
```

Expected differential: a pool inside the DMZ with an MFA and jump-host requirement is the control; a pool inside the control subnet or an always-on vendor tunnel is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
