# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `lolbins-and-signed-binary-abuse-driver-blocklist-gaps`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Driver inventory with hashes

**Expected differential.** A third-party driver from a user-writable path with a hash absent from the blocklist is the candidate; an in-box driver is not.

```bash
driverquery /v /fo csv | Select-String -Pattern 'Kernel Driver'
Get-ChildItem C:\Windows\System32\drivers -Filter *.sys | Get-FileHash -Algorithm SHA256
```

## Enforcement state

**Expected differential.** Blocklist enable 1 with HVCI running proves enforcement; either missing proves the gap.

```bash
Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -Property SecurityServicesRunning
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
