# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`pivoting-and-tunneling-dns-and-icmp-tunnels`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `pivoting-and-tunneling-dns-and-icmp-tunnels`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Delegation audit

**Expected differential.** An NS record pointing outside the organisation proves a delegation that could carry a tunnel; no such record proves there is none.

```bash
dig +short NS corp.example
dig +short NS _tunnel.corp.example
```

## Query statistics

**Expected differential.** Sustained long, high-entropy names prove encoded payloads; short dictionary-like names prove normal resolution.

```bash
dig +short TXT test.corp.example
tcpdump -ni eth0 -c 200 'udp port 53' | Select-String 'length'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
