# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-service-and-scheduled-task-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sc.exe` | `sc.exe create tempsvc binPath= 'C:\Windows\Temp\bin.exe' start= demand` | Create a service, lab only and removed after | Windows |
| `schtasks` | `schtasks /create /tn t /tr cmd.exe /sc once /st 23:59` | Create a task, lab only | Windows |
| `Get-ScheduledTask` | `Get-ScheduledTask &#124; Select-Object TaskName,TaskPath,Author,State` | Task inventory with author | Windows |
| `Get-CimInstance` | `Get-CimInstance Win32_Service &#124; Select-Object Name,PathName,StartName` | Service inventory | Windows |
| `autorunsc` | `autorunsc.exe -a s -accepteula -h -s` | Signed autorun inventory | Windows |

## Minimal Lab Validation Script

Inventory the object population and its authorisation; creation is a separate authorised step that must be reverted.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("recent_services", ps(
    "Get-CimInstance Win32_Service | Where-Object { $_.PathName -notlike '*System32*' } | "
    "Select-Object Name,PathName,StartName | ConvertTo-Csv -NoTypeInformation")[:400])
print("non_ms_tasks", ps(
    "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | "
    "Select-Object TaskName,TaskPath,Author | ConvertTo-Csv -NoTypeInformation")[:400])
```

## Flag Notes

- `start= demand` keeps a lab service from starting automatically; it must still be deleted afterwards.
- `/sc once /st` schedules a single run, which bounds the effect of a test task.
- `-a s` in autorunsc limits the scan to services, which is faster and less noisy than all autoruns.
