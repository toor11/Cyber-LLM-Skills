# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-lateral-movement-rdp-and-session-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-lateral-movement-rdp-and-session-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Negotiation and policy

**Expected differential.** A reply without `PROTOCOL_HYBRID` proves NLA is optional; `fDenyTSConnections` of 1 proves RDP is off.

```bash
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info 10.20.30.20
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
```

## Session and shadowing state

**Expected differential.** An existing session and shadowing configured permissive prove observation is possible; no session proves there is nothing to shadow.

```bash
query session /server:10.20.30.20
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name Shadow
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
