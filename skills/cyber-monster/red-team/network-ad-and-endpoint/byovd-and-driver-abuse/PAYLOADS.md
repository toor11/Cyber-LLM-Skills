# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`byovd-and-driver-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `byovd-and-driver-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Driver provenance

**Expected differential.** A third-party driver from a user-writable path with a valid signature is the candidate; an in-box Microsoft driver is not.

```bash
driverquery /v /fo csv | ConvertFrom-Csv | Where-Object { $_.'Module Type' -eq 'Kernel Driver' }
Get-AuthenticodeSignature C:\Windows\System32\drivers\<name>.sys | Select-Object Status,SignerCertificate
```

## Enforcement state

**Expected differential.** Blocklist enable 0 proves no consultation; enable 1 with HVCI proves enforcement.

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config' /v VulnerableDriverBlocklistEnable
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object AvailableSecurityProperties,CodeIntegrityPolicyEnforcementStatus
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
