# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`service-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nmap` | `nmap -sV --version-intensity 5 -p- --open -oA svc 10.20.30.20` | Version detection across the port set | Linux / macOS / Windows |
| `netexec` | `netexec smb 10.20.30.20 --shares --sessions` | SMB metadata with a supplied identity | Linux / Windows |
| `ldapsearch` | `ldapsearch -x -H ldap://10.20.30.20 -s base -b '' namingContexts` | Root DSE without authentication | Linux / macOS |
| `snmpwalk` | `snmpwalk -v2c -c public 10.20.30.20 1.3.6.1.2.1.1` | Device identity from the management plane | Linux / macOS |
| `rpcclient` | `rpcclient -U '' -N 10.20.30.20 -c 'enumdomusers'` | Anonymous MSRPC surface | Linux |

## Minimal Lab Validation Script

Read one attribute per protocol from the response itself, so the report cites the wire rather than a tool's summary line.

```python
import socket

def smb_dialects(host, port=445, timeout=5):
    # SMB2 negotiate with a minimal dialect list; the reply names the chosen dialect
    pkt = bytes.fromhex("000000a4fe534d42400000000000000000000000000000000000000000000000"
                        "0000000000000000000000000000000000000000000000000000000000000000")
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(pkt)
        head = s.recv(128)
    print(host, "dialect-bytes", head[4:8].hex(), "len", len(head))

smb_dialects("10.20.30.20")
```

## Flag Notes

- `--version-intensity` below 5 reduces probe count; use it when the target is fragile or monitored.
- `-sV` alone does not prove configuration, only product family; pair with a protocol-specific read.
- `--script smb2-security-mode` reports signing requirements without authenticating.
