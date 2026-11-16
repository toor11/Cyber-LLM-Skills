# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Hook comparison

**Expected differential.** A disk-versus-memory difference proves a hook; equality proves the function is unhooked for that process.

```bash
Get-Process -Name lsass | Select-Object ProtectionLevel
Get-Process -Name edragent -ErrorAction SilentlyContinue | Select-Object ProtectionLevel
```

## Kernel telemetry survival

**Expected differential.** An alert that survives a direct system call proves kernel-side observation; no alert with an unhooked process proves a hook-only design.

```bash
wevtutil gl Microsoft-Windows-Sysmon/Operational
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty SecurityServicesConfigured
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
