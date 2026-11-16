# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`lolbins-and-signed-binary-abuse-download-and-staging`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `certutil` | `certutil -urlcache -split -f <url> <path>` | Download through a signed binary, lab only | Windows |
| `bitsadmin` | `bitsadmin /transfer job <url> <path>` | Background transfer, lab only | Windows |
| `Get-WinEvent` | Filter Sysmon 11 and 22 on the binary name | Creation and DNS evidence | Windows |
| `Get-NetFirewallRule` | `Get-NetFirewallRule -Direction Outbound -Enabled True` | Egress policy state | Windows |
| `sigcheck` | `sigcheck.exe -a -h <staged-file>` | Provenance of the staged content | Windows |

## Minimal Lab Validation Script

Report which signed binaries can reach the network and where egress is permitted; no content is downloaded by this probe.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout

rules = ps("Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow | "
           "Select-Object DisplayName | ConvertTo-Csv -NoTypeInformation")
any_dest = [ln for ln in rules.splitlines() if "any" in ln.lower()]
print("outbound_allow_rules", len(rules.splitlines()) - 1, "any_destination_hints", any_dest[:3])

recent = ps("Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=11} "
            "-MaxEvents 60 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message")
for name in ("certutil", "bitsadmin", "curl"):
    print(name, sum(1 for ln in recent.splitlines() if name in ln.lower()))
```

## Flag Notes

- Listing outbound allow rules with their destinations is the egress-policy evidence.
- Sysmon 11 shows file creation with `Image` and `TargetFilename`, which ties the file to the binary.
- Sysmon 22 shows the DNS query, which is the network half when a proxy hides the connection.
