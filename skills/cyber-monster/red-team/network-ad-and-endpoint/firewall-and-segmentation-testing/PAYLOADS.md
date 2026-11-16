# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`firewall-and-segmentation-testing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `firewall-and-segmentation-testing`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Known-permitted versus known-denied

**Expected differential.** The permitted tuple completes and the denied tuple fails with `filtered` or an ICMP admin-prohibited, which calibrates the probe before the real test.

```bash
nmap -Pn -p 53,445 --reason 10.20.1.10
nmap -Pn -p 3389 --reason 10.20.40.15
```

## Path localisation

**Expected differential.** A traceroute that stops at the last hop before the destination points at a host firewall; one that stops earlier points at an intermediate ACL.

```bash
traceroute -T -p 443 10.20.40.15
nmap -Pn -p 443 --traceroute 10.20.40.15
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
