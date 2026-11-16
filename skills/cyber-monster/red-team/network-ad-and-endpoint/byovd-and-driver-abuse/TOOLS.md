# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`byovd-and-driver-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `driverquery` | `driverquery /v /fo csv` | Loaded driver inventory with signer | Windows |
| `sigcheck` | `sigcheck.exe -a -h <driver>.sys` | Hash and signer chain | Windows |
| `Get-AuthenticodeSignature` | `Get-AuthenticodeSignature <driver>.sys` | Signature validity | Windows |
| `LOLDrivers` | Search by hash or publisher | Classification and HVCI loadability | Cross-platform |
| `Get-WinEvent` | Sysmon 6 and System 7045 filters | Load and installation events | Windows |

## Minimal Lab Validation Script

Report driver provenance and enforcement state; no driver is loaded by this probe.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

third_party = ps("Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -and "
                 "$_.PathName -notlike '*System32\\drivers*' } | "
                 "Select-Object Name,PathName,StartMode | ConvertTo-Csv -NoTypeInformation")
print("third_party_drivers", (third_party or "").splitlines()[:6])
print("blocklist", ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' "
                      "-ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable") or "unset")
print("recent_driver_installs", ps("(Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} "
                                   "-MaxEvents 20 -ErrorAction SilentlyContinue | "
                                   "Where-Object { $_.Message -match 'kernel' }).Count") or "0")
```

## Flag Notes

- `-notlike '*System32\drivers*'` isolates the interesting set, since in-box drivers stay in that path.
- `Get-AuthenticodeSignature` gives the signer and validity without an external tool.
- System event 7045 with `kernel` in the message is the driver-installation event.
