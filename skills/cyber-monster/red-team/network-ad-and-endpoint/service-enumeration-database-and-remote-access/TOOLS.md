# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`service-enumeration-database-and-remote-access`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nmap` | `nmap -p 1433,3306,3389,5432 --script ms-sql-info,mysql-info,rdp-enum-encryption 10.20.30.40` | Pre-authentication metadata across engines | Cross-platform |
| `impacket-mssqlclient` | `impacket-mssqlclient -windows-auth DOMAIN/user@10.20.30.40` | Authenticated session for authorisation checks | Linux / Windows |
| `mysql` | `mysql --ssl-mode=REQUIRED -h 10.20.30.40 -e 'SELECT VERSION();'` | Confirms TLS enforcement with a real client | Cross-platform |
| `xfreerdp` | `xfreerdp /v:10.20.30.41 /cert:ignore +auth-only` | Proves NLA negotiation with a client | Linux / macOS |
| `nmap` | `nmap -p 5432 --script pgsql-brute --script-args brute.firstonly=1` | Avoid; use `pgsql-info` style reads instead of credential attempts | Cross-platform |

## Minimal Lab Validation Script

Read the negotiation fields only; never send a credential, so the script stays inside non-destructive verification.

```python
import socket, struct

def mssql_prelogin(host, port=1433, timeout=4):
    # TDS pre-login: one option token 0x00 (VERSION) plus terminator
    payload = bytes.fromhex("1201002f0000000100000000001a00060100200001020021000103002200040400260001ff09000000000000000000")
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(payload)
        reply = s.recv(512)
    enc = reply.hex().find("04")
    print(host, "prelogin_reply_len", len(reply), "first_bytes", reply[:16].hex())

mssql_prelogin("10.20.30.40")
```

## Flag Notes

- `--script ms-sql-info` returns instance and version from pre-login only; it does not authenticate.
- `rdp-enum-encryption` reports the selected protocol, which is the NLA evidence.
- `--ssl-mode=REQUIRED` on the client side proves enforcement from the server, not just a client preference.
