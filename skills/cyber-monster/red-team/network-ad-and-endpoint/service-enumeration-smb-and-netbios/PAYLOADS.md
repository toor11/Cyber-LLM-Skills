# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`service-enumeration-smb-and-netbios`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `service-enumeration-smb-and-netbios`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Signing requirement

**Expected differential.** A negotiate reply with `signing not required` proves relay feasibility; `signing required` proves the control holds.

```bash
nmap -p 445 --script smb2-security-mode 10.20.30.20
nmap -p 445 --script smb2-capabilities 10.20.30.20
```

## Anonymous surface

**Expected differential.** A share list returned with no credentials proves anonymous read exposure; access denied proves the boundary.

```bash
netexec smb 10.20.30.20 --shares -u '' -p ''
smbclient -L //10.20.30.20 -N -m SMB3
```

## Legacy name service

**Expected differential.** NBNS answers with the host's registered names prove the legacy stack is live even if SMB2 is negotiated.

```bash
nmblookup -A 10.20.30.20
nmblookup -T '*\'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
