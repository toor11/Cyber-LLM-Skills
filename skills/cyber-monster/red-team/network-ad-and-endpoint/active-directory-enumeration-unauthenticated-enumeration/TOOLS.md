# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-enumeration-unauthenticated-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nslookup` | `nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.example` | Domain and DC discovery via DNS | Cross-platform |
| `rpcclient` | `rpcclient -U '%' -N dc01 -c 'dsroledominfo'` | Null-session RPC surface | Linux |
| `ldapsearch` | `ldapsearch -x -H ldap://dc01 -s base -b '' '+'` | Anonymous root DSE with operational attributes | Linux / macOS |
| `netexec` | `netexec smb dc01 -u '' -p '' --users` | Anonymous user enumeration attempt | Linux / Windows |
| `enum4linux-ng` | `enum4linux-ng -A dc01 -oJ out.json` | Consolidated null-session checks | Linux |

## Minimal Lab Validation Script

Probe the anonymous surface in a fixed order and print the server's own error string, because the error is the evidence.

```python
import subprocess

def probe(label, cmd):
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    out = (res.stdout + res.stderr).strip().splitlines()
    print(label, "rc", res.returncode, "|", out[0] if out else "no output")

probe("rootdse", ["ldapsearch", "-x", "-H", "ldap://10.20.30.10", "-s", "base", "-b", "", "namingContexts"])
probe("anon-search", ["ldapsearch", "-x", "-H", "ldap://10.20.30.10", "-b",
                       "DC=corp,DC=example", "(objectClass=user)", "sAMAccountName"])
probe("null-smb", ["rpcclient", "-U", "%", "-N", "10.20.30.10", "-c", "lsaquery"])
```

## Flag Notes

- `-U '%' -N` sends an empty user and no password, which is the null session form rpcclient expects.
- `-s base -b ''` is the only anonymous LDAP form that is reliably served.
- `-A` in enum4linux-ng enables all checks, which is noisier; use `-u`/`-p` to keep the unauthenticated run separate.
