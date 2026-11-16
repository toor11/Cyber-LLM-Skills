# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-lateral-movement-winrm-and-wmi`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-lateral-movement-winrm-and-wmi`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Listener and group state

**Expected differential.** A plaintext listener plus broad group membership proves any authenticated principal can open a shell; an HTTPS listener with a named group does not.

```bash
winrm enumerate winrm/config/listener
net localgroup 'Remote Management Users'
```

## Execution telemetry shape

**Expected differential.** A 4688 with `wsmprovhost.exe` or `WmiPrvSE.exe` as parent proves the remote execution path; no such event proves the protocol was not used to execute.

```bash
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 50 |
  Where-Object { $_.Message -match 'wsmprovhost|WmiPrvSE' }
netexec winrm 10.20.30.20 -u Administrator -H <hash> -x whoami
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
