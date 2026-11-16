# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`c2-infrastructure-and-redirectors`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `c2-infrastructure-and-redirectors`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Endpoint profile

**Expected differential.** A recent certificate with generic issuer fields on a brand-like name proves lookalike infrastructure; a match to the brand's stack does not.

```bash
openssl s_client -connect suspect.example:443 -servername suspect.example </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates
curl -sSI https://suspect.example/ --max-time 10
```

## Visibility gap

**Expected differential.** A permitted destination with no logged DNS query and no proxy host record proves the gap; either log proves partial coverage.

```bash
nslookup suspect.example 10.20.1.10
Get-DnsServerDiagnostics | Select-Object Queries
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
