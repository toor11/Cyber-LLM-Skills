# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`network-protocol-attacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `network-protocol-attacks`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Victim resolver state

**Expected differential.** A resolver cache entry pointing at an unexpected address, matching a name the victim just queried, is the differential that proves poisoning; an unchanged cache proves it did not take.

```bash
ip neigh show 10.20.30.1
Get-DnsClientCache | Where-Object Entry -match 'fileserver'
```

## Protocol availability

**Expected differential.** A response to an LLMNR or NBT-NS query from a host that should not be answering proves the answer path exists.

```bash
nmap -sU -p 5355 10.20.30.0/24 --open
nmblookup -U 10.20.30.25 -R 'FILESERVER<00>'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
