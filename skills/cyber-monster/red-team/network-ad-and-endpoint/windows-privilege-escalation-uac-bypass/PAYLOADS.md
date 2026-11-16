# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-privilege-escalation-uac-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-privilege-escalation-uac-bypass`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Policy and token state

**Expected differential.** A consent value of 0 with a Medium-integrity administrator token proves the bypass precondition; a filtered token proves the account is not an administrator.

```bash
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin,EnableLUA,FilterAdministratorToken
whoami /groups | Select-String 'Mandatory Label|Administrators'
```

## Integrity differential

**Expected differential.** A High-integrity child with a Medium-integrity parent proves elevation without consent; an unchanged Medium proves the control held.

```bash
whoami /groups /fo csv | Select-String 'Mandatory Label'
Get-Process -Id $PID | Select-Object Path
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
