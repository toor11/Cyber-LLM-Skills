# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ntlm-relay-and-coercion-coercion-primitives`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `ntlm-relay-and-coercion-coercion-primitives`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Service dependency state

**Expected differential.** A stopped spooler or EFS service proves the corresponding primitive is unavailable; a running service proves it is a candidate.

```bash
Get-Service Spooler,EFS,DFSR -ErrorAction SilentlyContinue
rpcclient -U 'lowpriv%pass' 10.20.30.10 -c 'lsaquery'
```

## Interface reachability

**Expected differential.** A successful bind proves the interface is exposed; a rejection proves the service is absent.

```bash
coercer scan -t 10.20.30.10 -u lowpriv -p pass -d corp.example
nmap -p 445,135 --script smb2-security-mode,rpc-grind 10.20.30.10
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
