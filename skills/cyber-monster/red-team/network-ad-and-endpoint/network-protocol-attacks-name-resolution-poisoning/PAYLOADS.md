# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`network-protocol-attacks-name-resolution-poisoning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `network-protocol-attacks-name-resolution-poisoning`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Broadcast protocol availability

**Expected differential.** A query on 5355 from the victim proves LLMNR is in use; silence proves it is disabled and the technique does not apply.

```bash
tcpdump -ni eth0 -c 20 'udp port 5355 and src host 10.20.30.50'
tcpdump -ni eth0 -c 20 'udp port 137 and src host 10.20.30.50'
```

## Victim-side result

**Expected differential.** A name resolving to the assessment address, followed by an SMB connection to it, is the differential; a resolution failure proves the control holds.

```bash
Resolve-DnsName fileserverx -LlmnrNetbiosOnly -ErrorAction SilentlyContinue
Get-SmbConnection -ServerName fileserverx -ErrorAction SilentlyContinue
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
