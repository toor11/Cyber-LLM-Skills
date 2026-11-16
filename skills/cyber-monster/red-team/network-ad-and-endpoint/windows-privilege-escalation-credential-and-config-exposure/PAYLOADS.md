# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-privilege-escalation-credential-and-config-exposure`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-privilege-escalation-credential-and-config-exposure`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Unattend artefacts

**Expected differential.** A readable unattend file with a `Password` element proves an encoded local credential; an absent file proves the image was cleaned.

```bash
Get-ChildItem C:\Windows\Panther,C:\Windows\System32\Sysprep -Filter 'unattend*' -ErrorAction SilentlyContinue
icacls C:\Windows\Panther\unattend.xml
```

## SYSVOL policy credentials

**Expected differential.** A `cpassword` attribute proves a recoverable domain credential published to every authenticated principal.

```bash
Get-ChildItem -Recurse '\\corp.example\SYSVOL' -Filter *.xml | Select-String 'cpassword'
find /mnt/sysvol -name '*.xml' -exec grep -l cpassword {} +
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
