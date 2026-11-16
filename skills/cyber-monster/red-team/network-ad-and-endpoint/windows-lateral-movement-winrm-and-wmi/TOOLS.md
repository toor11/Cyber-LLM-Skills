# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-lateral-movement-winrm-and-wmi`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `evil-winrm` | `evil-winrm -i 10.20.30.20 -u Administrator -H <hash>` | WinRM shell, lab only | Linux |
| `netexec` | `netexec winrm 10.20.30.20 -u Administrator -p pass -x whoami` | Single command over WinRM | Linux / Windows |
| `impacket-wmiexec` | `impacket-wmiexec corp.example/admin:pass@10.20.30.20 whoami` | WMI process creation | Linux / Windows |
| `winrm` | `winrm enumerate winrm/config/listener` | Listener and transport state | Windows |
| `Invoke-Command` | `Invoke-Command -ComputerName fs01 -ScriptBlock { hostname }` | Native remoting for a controlled test | Windows |

## Minimal Lab Validation Script

Prove execution capability with one benign command and record the parent process, which is the durable evidence.

```python
import subprocess

def winrm_state(host):
    out = subprocess.run(["nmap", "-p", "5985,5986", "--reason", host],
                         capture_output=True, text=True).stdout
    return [ln.strip() for ln in out.splitlines() if "/tcp" in ln]

print("winrm_ports", winrm_state("10.20.30.20"))
print("members", subprocess.run(
    ["powershell", "-NoProfile", "-Command",
     "Get-CimInstance Win32_GroupUser | Where-Object { $_.GroupComponent -match 'Remote Management Users' }"],
    capture_output=True, text=True).stdout[:300])
```

## Flag Notes

- `-x` executes a single command over WinRM and is the least invasive form of the test.
- `enumerate winrm/config/listener` reports transport and port, which is the plaintext-versus-TLS evidence.
- `Get-CimInstance Win32_GroupUser` lists group membership without a remote session.
