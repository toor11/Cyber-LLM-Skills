# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`defense-evasion-and-log-tampering-indicator-removal`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `defense-evasion-and-log-tampering-indicator-removal`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Artefact set for one execution

**Expected differential.** A missing prefetch or `Amcache` entry for a binary with a confirmed execution is the finding; both present proves the record survived.

```bash
Get-ChildItem C:\Windows\Prefetch\*.pf | Where-Object Name -match 'SUSPECT'
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 50 | Select-String 'SUSPECT'
```

## Deletion records

**Expected differential.** A `UsnJrnl` delete reason for a named file proves removal even when the file is gone.

```bash
fsutil usn readjournal C: csv | Select-String 'FILE_DELETE' | Select-Object -First 10
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4699} -MaxEvents 20
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
