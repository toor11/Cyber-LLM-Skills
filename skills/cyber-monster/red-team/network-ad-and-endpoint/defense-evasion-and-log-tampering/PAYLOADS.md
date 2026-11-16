# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`defense-evasion-and-log-tampering`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `defense-evasion-and-log-tampering`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Integrity and continuity

**Expected differential.** A non-monotonic record id or a checksum mismatch proves file-level tampering; a clean sequence proves integrity.

```bash
Get-WinEvent -LogName Security -MaxEvents 1 | Select-Object RecordId,TimeCreated
wevtutil gli Security
```

## Tampering events

**Expected differential.** A 1102, 1100 or 4719 in the window is direct evidence; their absence with a peer-relative gap is indirect evidence.

```bash
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102,1100,4719} -MaxEvents 20
Get-WinEvent -FilterHashtable @{LogName='System';Id=104} -MaxEvents 20
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
