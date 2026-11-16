# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`edr-evasion-and-amsi-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-MpComputerStatus` | `Get-MpComputerStatus` | Tamper protection and real-time state | Windows |
| `Get-WinEvent -ListLog` | `Get-WinEvent -ListLog * -ErrorAction SilentlyContinue` | Available telemetry channels | Windows |
| `logman` | `logman query -ets` | Active ETW sessions | Windows |
| `Get-CimInstance Win32_DeviceGuard` | DeviceGuard namespace query | HVCI and VBS state | Windows |
| `driverquery` | `driverquery /v /fo csv` | Early-launch and filter drivers present | Windows |

## Minimal Lab Validation Script

Inventory the telemetry surfaces and their protection; no tampering is performed by this probe.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("amsi", ps("(Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers' "
                 "-ErrorAction SilentlyContinue).PSChildName -join ','") or "none")
print("tamper", ps("(Get-MpComputerStatus).IsTamperProtected"))
print("sysmon_log", ps("(Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' "
                       "-ErrorAction SilentlyContinue).RecordCount") or "absent")
print("etw_sessions", subprocess.run(["logman", "query", "-ets"],
                                     capture_output=True, text=True).stdout.count("\n"))
```

## Flag Notes

- `logman query -ets` lists active trace sessions, which is the ETW coverage evidence.
- `Get-WinEvent -ListLog *` enumerates available channels, distinguishing 'not collected' from 'not available'.
- `driverquery` reveals filter drivers, which are where many EDR products hook.
