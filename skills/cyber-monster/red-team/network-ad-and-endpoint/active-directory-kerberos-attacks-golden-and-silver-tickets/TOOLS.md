# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-kerberos-attacks-golden-and-silver-tickets`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `impacket-ticketer` | `impacket-ticketer -nthash <krbtgt-hash> -domain-sid S-1-5-21-x -domain corp.example administrator` | Forge a TGT in an authorised lab | Linux / Windows |
| `Rubeus` | `Rubeus.exe golden /rc4:<hash> /user:administrator /domain:corp.example /sid:S-1-5-21-x` | Golden ticket from a Windows host, lab only | Windows |
| `Get-ADUser` | `Get-ADUser krbtgt -Properties PasswordLastSet,msDS-KeyVersionNumber` | Rotation state | Windows |
| `repadmin` | `repadmin /showobjmeta dc01 'CN=krbtgt,CN=Users,DC=corp,DC=example'` | Per-DC replication of the key change | Windows |
| `klist` | `klist -e -k` | Inspect a ticket cache for anomalous encryption types | Windows |

## Minimal Lab Validation Script

Report key age and rotation completeness rather than forging anything; the rotation state is the finding and needs no ticket.

```python
from ldap3 import Server, Connection, NTLM
from datetime import datetime, timezone

srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=example", "(sAMAccountName=krbtgt)",
            attributes=["pwdLastSet", "msDS-KeyVersionNumber"])
for e in conn.entries:
    if e.pwdLastSet.value in (None, 0):
        print("krbtgt key never set on this object")
        continue
    ts = datetime.fromtimestamp(e.pwdLastSet.value / 10_000_000 - 11644473600, tz=timezone.utc)
    print("krbtgt_pwd_last_set", ts.isoformat(), "key_version", e.msDS_KeyVersionNumber.value)
```

## Flag Notes

- `msDS-KeyVersionNumber` increments on each rotation, so it shows how many times the key has changed.
- `/showobjmeta` proves the change reached every DC, which is what makes a double rotation effective.
- `klist -e` reveals tickets whose encryption type does not match the account's configuration.
