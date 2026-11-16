# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`process-injection-techniques-classic-and-apc-injection`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Sysmon` | Events 8 and 10 | Thread creation and process access | Windows |
| `Get-WinEvent` | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10}` | Access events with masks | Windows |
| `Process Explorer` | Threads tab | Existing thread inventory per process | Windows |
| `api-monitor` | Filter on `CreateRemoteThread` and `QueueUserAPC` | API-level confirmation in a lab | Windows |
| `Get-CimInstance Win32_DeviceGuard` | DeviceGuard namespace | HVCI and VBS state | Windows |

## Minimal Lab Validation Script

Report the access-execution pair and the source baseline; no injection is performed.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

access = ps("Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} "
            "-MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message")
threads = ps("Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=8} "
             "-MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message")

write_masks = [ln for ln in access.splitlines() if "0x1F0FFF" in ln or "0x0008" in ln]
cross = [ln for ln in threads.splitlines() if "CreateRemoteThread" in ln]
print("write_access_events", len(write_masks), "remote_thread_events", len(cross))
print("sample", (write_masks[:1] + cross[:1]))
```

## Flag Notes

- `GrantedAccess` values `0x1F0FFF` and `0x0008` are the write-capable masks worth filtering on.
- Grouping event 10 by `SourceImage` produces the baseline in one pass.
- API Monitor in a lab confirms which API produced the event, which is useful for rule authoring.
