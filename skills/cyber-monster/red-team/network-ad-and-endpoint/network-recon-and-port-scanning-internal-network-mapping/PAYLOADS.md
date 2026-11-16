# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`network-recon-and-port-scanning-internal-network-mapping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `network-recon-and-port-scanning-internal-network-mapping`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Layer-two presence versus routed reachability

**Expected differential.** A host in the ARP table that ignores ICMP and TCP is present with filtering; a host absent from ARP and silent to TCP is not on this segment.

```bash
ip neigh show dev eth0
nmap -sn -PR 10.20.30.0/24 -oG l2.gnmap
nmap -sn -PE -PS22,445 10.20.30.0/24 -oG l3.gnmap
```

## Allowed-path baseline

**Expected differential.** The permitted service answers from both sides; the suspect edge answers only from the permitted side, which is the boundary proving itself.

```bash
nmap -Pn -p 53 --reason 10.20.1.10
nmap -Pn -p 139,445,3389 --reason 10.20.40.0/24 --open
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
