# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`network-recon-and-port-scanning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `network-recon-and-port-scanning`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Discovery differential

**Expected differential.** A host that answers ARP but not ICMP echo is up with ICMP filtered; a host that answers neither is either absent or fully filtered and needs a TCP probe before you write it off.

```bash
nmap -sn -PR 10.20.30.0/24 -oG arp-sweep.gnmap
nmap -sn -PE 10.20.30.0/24 -oG icmp-sweep.gnmap
nmap -sn -PS22,80,443,445 10.20.30.0/24 -oG syn-sweep.gnmap
```

## Filtered versus closed

**Expected differential.** The same port answered with RST on one host and silence on another proves the second host has a drop rule, not a missing service.

```bash
nmap -Pn -p 445 --reason 10.20.30.11 10.20.30.12
tcpdump -ni eth0 'tcp port 445 and (tcp[tcpflags] & tcp-rst != 0)'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
