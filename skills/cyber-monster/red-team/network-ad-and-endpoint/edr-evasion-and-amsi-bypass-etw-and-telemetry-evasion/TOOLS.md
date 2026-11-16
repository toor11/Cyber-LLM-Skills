# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `logman` | `logman query -ets` | Active ETW sessions | Windows |
| `Get-WinEvent -ListLog` | `Get-WinEvent -ListLog *` | Channel record counts and state | Windows |
| `wevtutil` | `wevtutil gl Security` | Channel enablement and retention | Windows |
| `Get-Service` | `Get-Service EventLog` | Logging service state | Windows |
| `Sysmon` | Event 8 and 10 filters | Injection into telemetry processes | Windows |

## Minimal Lab Validation Script

Report session inventory and per-channel counts for a fixed window, which is the suppression evidence.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("ets_sessions", subprocess.run(["logman", "query", "-ets"],
                                     capture_output=True, text=True).stdout.count("\n"))
for channel in ("Security", "Microsoft-Windows-Sysmon/Operational",
                "Microsoft-Windows-PowerShell/Operational"):
    info = ps(f"Get-WinEvent -ListLog '{channel}' -ErrorAction SilentlyContinue | "
              f"Select-Object RecordCount,LastWriteTime | ConvertTo-Json -Compress")
    print(channel, info or "absent")
print("eventlog_service", ps("(Get-Service EventLog).Status + '/' + (Get-Service EventLog).StartType"))
```

## Flag Notes

- `logman query -ets` lists only running sessions, which is what a consumer change removes.
- `RecordCount` and `LastWriteTime` together distinguish an idle channel from a stopped one.
- `wevtutil gl` reports whether a channel is enabled and its retention, which bounds the investigation window.
