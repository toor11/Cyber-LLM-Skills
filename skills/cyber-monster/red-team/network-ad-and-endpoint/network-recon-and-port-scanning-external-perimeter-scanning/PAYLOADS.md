# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`network-recon-and-port-scanning-external-perimeter-scanning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `network-recon-and-port-scanning-external-perimeter-scanning`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Fronting layer identification

**Expected differential.** If the `server` header and TLS issuer match the CDN fleet rather than the internal inventory, the port is the edge, and the origin remains unproven.

```bash
curl -sS -D - -o /dev/null https://portal.example.com --max-time 10
openssl s_client -connect 198.51.100.20:443 -servername portal.example.com </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -ext subjectAltName
```

## Two-source reachability

**Expected differential.** SYN-ACK from one egress and silence from another is provider filtering; both silent with RST from a third is a host firewall.

```bash
nmap -Pn -p 443,8443 --reason 198.51.100.20
nmap -Pn -p 443,8443 --reason --data-length 0 198.51.100.20
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
