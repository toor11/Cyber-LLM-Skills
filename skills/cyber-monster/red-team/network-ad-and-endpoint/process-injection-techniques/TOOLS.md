# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`process-injection-techniques`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Sysmon` | Event 8, 10 and 25 filters | Thread, access and tampering events | Windows |
| `Get-WinEvent` | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10}` | Process access events | Windows |
| `auditpol` | `auditpol /get /subcategory:'Handle Manipulation'` | Object access auditing state | Windows |
| `Process Explorer` | Threads and modules view | Thread and module inventory for a target | Windows |
| `Get-CimInstance Win32_DeviceGuard` | DeviceGuard namespace | VBS and HVCI, which constrain kernel-level injection | Windows |

## Minimal Lab Validation Script

Report the telemetry coverage for the injection sequence; no code is injected by this probe.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("sysmon", ps("(Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' "
                   "-ErrorAction SilentlyContinue).RecordCount") or "absent")
for eid in (8, 10, 25):
    print("event", eid, ps(f"(Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational';Id={eid}}} "
                            f"-MaxEvents 5 -ErrorAction SilentlyContinue).Count") or "0")
print("handle_audit", ps("(auditpol /get /subcategory:'Handle Manipulation') -join ' '"))
```

## Flag Notes

- Counting recent events per id proves whether the channel is populated rather than merely present.
- `Handle Manipulation` auditing is the prerequisite for 4656 events on process objects.
- Sysmon event 25 requires a recent Sysmon version, so check the installed version alongside the event count.
