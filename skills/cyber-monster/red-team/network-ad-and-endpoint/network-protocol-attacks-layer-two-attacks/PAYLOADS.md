# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`network-protocol-attacks-layer-two-attacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `network-protocol-attacks-layer-two-attacks`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Passive trunk negotiation read

**Expected differential.** A DTP frame from an access port proves it will negotiate a trunk; no DTP frame proves negotiation is disabled.

```bash
tcpdump -ni eth0 -c 20 'ether[20:2] == 0x2004'
tcpdump -ni eth0 -c 20 'vlan'
```

## Switch-side state

**Expected differential.** A CAM count that jumps after flooding, or a root-bridge identity that changes after a BPDU, is device-side proof; unchanged state proves the control holds.

```bash
ssh admin@switch 'show mac address-table count'
ssh admin@switch 'show spanning-tree vlan 20 | include Root'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
