# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `driverquery` | `driverquery /v /fo csv` | Loaded drivers with signer | Windows |
| `sigcheck` | `sigcheck.exe -a -h *.sys` | Hash and publisher of driver files | Windows |
| `Get-AuthenticodeSignature` | `Get-AuthenticodeSignature C:\Windows\System32\drivers\x.sys` | Signature validity | Windows |
| `LOLDrivers` | Search by hash or driver name | Vulnerability classification and HVCI tag | Cross-platform |
| `Get-CimInstance Win32_DeviceGuard` | `Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard` | HVCI state | Windows |

## Minimal Lab Validation Script

Report driver hashes beside the blocklist and HVCI state, which is the evidence for a gap without loading anything.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

block = ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' "
           "-ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable")
hvci = ps("Get-CimInstance -ClassName Win32_DeviceGuard "
          "-Namespace root\\Microsoft\\Windows\\DeviceGuard | "
          "Select-Object -ExpandProperty SecurityServicesRunning")
third_party = ps("Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -and "
                 "$_.PathName -notlike '*System32\\drivers*' } | Select-Object -ExpandProperty Name")
print("blocklist_enable", block or "unset", "hvci_services", hvci or "none")
print("drivers_outside_system32", (third_party or "").split()[:10])
```

## Flag Notes

- `/v /fo csv` gives a parseable driver list including the signer, which is one of the three blocklist keys.
- `-a -h` on sigcheck prints the hash that the blocklist actually compares.
- `SecurityServicesRunning` containing 2 indicates HVCI, which is the enforcement mechanism.
