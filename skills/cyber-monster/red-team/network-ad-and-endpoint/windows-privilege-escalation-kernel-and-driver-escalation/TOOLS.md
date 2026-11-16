# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-privilege-escalation-kernel-and-driver-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `driverquery` | `driverquery /v /fo csv` | Loaded drivers with signer | Windows |
| `Get-CimInstance` | `Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard` | HVCI and VBS status | Windows |
| `sigcheck` | `sigcheck.exe -a -h C:\path\driver.sys` | Hash, signer and version | Windows |
| `LOLDrivers` | Search the catalogue by hash or name | Vulnerability classification and HVCI tag | Cross-platform |
| `Get-AuthenticodeSignature` | `Get-AuthenticodeSignature C:\path\driver.sys` | Signature validity without external tools | Windows |

## Minimal Lab Validation Script

Inventory drivers with hashes and protection state, which is the evidence for a blocklist gap without loading anything.

```python
import subprocess

ps = ("Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' | "
      "Select-Object Name,PathName | ConvertTo-Json -Compress")
out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                     capture_output=True, text=True).stdout
print("drivers_json_len", len(out))

hvci = ("Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root\\Microsoft\\Windows\\DeviceGuard | "
        "Select-Object -ExpandProperty SecurityServicesRunning")
print("security_services_running",
      subprocess.run(["powershell", "-NoProfile", "-Command", hvci],
                     capture_output=True, text=True).stdout.strip())

blocklist = ("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' "
             "-ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable")
print("blocklist_enable",
      subprocess.run(["powershell", "-NoProfile", "-Command", blocklist],
                     capture_output=True, text=True).stdout.strip())
```

## Flag Notes

- `/v` adds the signer and state columns; `/fo csv` makes the output parseable.
- `-a -h` in sigcheck prints the SHA256, which is the key the blocklist uses.
- `SecurityServicesRunning` value 2 indicates HVCI is running, which is what blocks most vulnerable drivers.
