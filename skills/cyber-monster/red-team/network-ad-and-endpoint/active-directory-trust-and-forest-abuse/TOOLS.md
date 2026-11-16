# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-trust-and-forest-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `netdom` | `netdom trust corp.example /domain:partner.example /quarantine` | SID-filtering state per trust | Windows |
| `Get-ADTrust` | `Get-ADTrust -Filter * -Properties *` | Trust direction, type and attributes | Windows |
| `nltest` | `nltest /domain_trusts /all_trusts /v` | Trust enumeration from a member host | Windows |
| `bloodhound-python` | `bloodhound-python -c Trusts -d corp.example -u lowpriv -p pass -ns 10.20.30.10 --zip` | Trust edges for path analysis | Linux / Windows |
| `Get-Acl` | `Get-Acl 'AD:CN=FS01,OU=Servers,DC=corp,DC=example'` | Selective authentication ACEs | Windows |

## Minimal Lab Validation Script

Report trust direction, type, SID filtering and selective authentication together, since no single attribute decides the boundary.

```python
from ldap3 import Server, Connection, NTLM

srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("CN=System,DC=corp,DC=example", "(objectClass=trustedDomain)",
            attributes=["name", "trustDirection", "trustType", "trustAttributes"])
for e in conn.entries:
    attrs = int(e.trustAttributes.value or 0)
    print(e.name, "direction", e.trustDirection.value, "type", e.trustType.value,
          "quarantined", bool(attrs & 0x4),
          "tgt_delegation", bool(attrs & 0x80000))
```

## Flag Notes

- `/quarantine` without a value reads the state; with `:Yes` it changes it, so read first.
- `/verify` tests the trust with the trust password, which is a read-only liveness check.
- `-Properties *` is needed for `SIDFilteringQuarantined`, which is not in the default set.
