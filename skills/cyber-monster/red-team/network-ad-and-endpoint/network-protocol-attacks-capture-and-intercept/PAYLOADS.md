# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`network-protocol-attacks-capture-and-intercept`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `network-protocol-attacks-capture-and-intercept`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Baseline capture on an access port

**Expected differential.** Only broadcast and own traffic proves an ordinary access port; unicast between other hosts proves a mirror.

```bash
tcpdump -ni eth0 -c 200 'not broadcast and not multicast'
tcpdump -ni eth0 -c 50 'ether dst not 00:11:22:33:44:55'
```

## Victim neighbour state

**Expected differential.** The victim's entry changing to the assessment host MAC proves the redirect took; an unchanged entry proves it did not.

```bash
ip neigh show 10.20.30.1 dev eth0
Get-NetNeighbor -IPAddress 10.20.30.1 | Format-List
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
