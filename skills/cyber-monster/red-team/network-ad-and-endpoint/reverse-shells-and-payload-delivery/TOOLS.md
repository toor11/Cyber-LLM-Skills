# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`reverse-shells-and-payload-delivery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-NetTCPConnection` | `Get-NetTCPConnection -State Established` | Established channels with owning process | Windows |
| `Sysmon` | Event 1 and 3 correlation | Process and network pairs | Windows |
| `ss` | `ss -tunp` | Established sockets on Linux | Linux |
| `Get-NetFirewallRule` | `Get-NetFirewallRule -Direction Outbound` | Egress policy state | Windows |
| `auditd` | `ausearch -m execve -ts recent` | Execution records on Linux | Linux |

## Minimal Lab Validation Script

Correlate the shell's parent process with its outbound connection, which is the whole finding.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

conns = ps("Get-NetTCPConnection -State Established | "
           "Select-Object RemoteAddress,RemotePort,OwningProcess | ConvertTo-Csv -NoTypeInformation")
for line in conns.splitlines()[:12]:
    print(line)
print("interpreter_children", ps(
    "Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -and "
    "$_.Name -match 'cmd.exe|powershell.exe|pwsh.exe' } | Select-Object Name,ParentProcessId | "
    "ConvertTo-Csv -NoTypeInformation")[:300])
```

## Flag Notes

- `OwningProcess` in `Get-NetTCPConnection` ties a connection to the process that made it, which is the correlation key.
- `-State Established` filters out listening sockets, which are not egress.
- `ausearch -m execve` gives execution records on Linux, which pairs with socket records.
