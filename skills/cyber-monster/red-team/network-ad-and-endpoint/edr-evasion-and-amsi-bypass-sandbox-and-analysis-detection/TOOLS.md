# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-CimInstance Win32_ComputerSystem` | `Get-CimInstance Win32_ComputerSystem` | CPU and memory properties a sample reads first | Windows |
| `Get-CimInstance Win32_LogicalDisk` | `Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"` | Disk size property | Windows |
| `driverquery` | `driverquery /v /fo csv` | Hypervisor and analysis driver artefacts | Windows |
| `Get-Process` | `Get-Process &#124; Where-Object Name -match 'procmon&#124;wireshark&#124;x64dbg'` | Analysis tool processes present | Windows |
| `systeminfo` | `systeminfo` | Consolidated environment properties | Windows |

## Minimal Lab Validation Script

Compare environment properties against a production baseline; no sample is executed by this probe.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("cpu_mem", ps("Get-CimInstance Win32_ComputerSystem | "
                    "Select-Object NumberOfProcessors,TotalPhysicalMemory | ConvertTo-Json -Compress"))
print("disk_gb", ps("[math]::Round((Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").Size/1GB)"))
print("uptime_days", ps("[math]::Round(((Get-Date)-(Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalDays,1)"))
print("vm_drivers", ps("(driverquery /v /fo csv | Select-String -Pattern 'vmware|vbox|hyper-v|xen').Count"))
```

## Flag Notes

- CPU and memory values are the first properties most samples read, so they are the first baseline to fix.
- Uptime above a week removes the freshest-environment discriminator.
- Hypervisor driver names are a reliable environment tell on Windows guests.
