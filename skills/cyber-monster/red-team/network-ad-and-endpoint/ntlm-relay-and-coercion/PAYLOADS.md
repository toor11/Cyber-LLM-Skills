# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ntlm-relay-and-coercion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `ntlm-relay-and-coercion`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Target signing state

**Expected differential.** A host with signing not required is a viable relay target; signing required is not.

```bash
netexec smb 10.20.30.0/24 --gen-relay-list relay.txt
nmap -p445 --script smb2-security-mode --script-args smb2-security-mode.cdbrowser=true 10.20.30.20
```

## Coercion reachability

**Expected differential.** The RPC interface binding successfully proves the primitive is available; a bind rejection proves the service is not running.

```bash
coercer scan -t 10.20.30.10 -u lowpriv -p pass -d corp.example --filter-protocol-name MS-RPRN
rpcclient -U 'lowpriv%pass' 10.20.30.10 -c 'getusername'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
