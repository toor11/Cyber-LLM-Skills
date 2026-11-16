# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`service-enumeration-smb-and-netbios`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `netexec` | `netexec smb 10.20.30.0/24 -u user -p pass --shares --signing` | Share and signing inventory with one identity | Linux / Windows |
| `smbclient` | `smbclient -L //10.20.30.20 -N -m SMB3` | Anonymous share listing | Linux / macOS |
| `nmap` | `nmap -p139,445 --script smb2-security-mode,smb-os-discovery 10.20.30.20` | Negotiation and OS metadata | Linux / macOS / Windows |
| `nmblookup` | `nmblookup -A 10.20.30.20` | NetBIOS name table per address | Linux |
| `smbmap` | `smbmap -H 10.20.30.20 -u user -p pass --no-banner` | Per-share read/write permission view | Linux / Windows |

## Minimal Lab Validation Script

Read signing state and dialect from the negotiate exchange itself, so the relay candidate list is derived from protocol evidence.

```python
from impacket.smbconnection import SMBConnection

def inspect(host, user="", password=""):
    conn = SMBConnection(host, host, sess_port=445, timeout=5)
    conn.login(user, password, "", "")
    dialect = conn.getDialect()
    signing = conn.isSigningRequired()
    print(host, "dialect", dialect, "signing_required", signing,
          "server_os", conn.getServerOS())

inspect("10.20.30.20")
```

## Flag Notes

- `--signing` prints the requirement per host, which is the field that decides relay feasibility.
- `-m SMB3` forces the modern dialect so an SMB1 fallback does not mask the real configuration.
- `--no-banner` keeps scripted output diffable across runs.
