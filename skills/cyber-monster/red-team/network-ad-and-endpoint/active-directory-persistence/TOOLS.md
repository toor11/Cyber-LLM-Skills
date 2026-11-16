# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-ADUser` | `Get-ADUser krbtgt -Properties PasswordLastSet,msDS-KeyVersionNumber` | Key rotation state | Windows |
| `repadmin` | `repadmin /showobjmeta dc01 'CN=krbtgt,CN=Users,DC=corp,DC=example'` | Per-DC replication of key changes | Windows |
| `Get-Acl` | `Get-Acl 'AD:CN=AdminSDHolder,CN=System,DC=corp,DC=example'` | Propagation-source ACL | Windows |
| `PowerView` | `Get-DomainObjectAcl -ResolveGUIDs -Identity 'CN=AdminSDHolder,CN=System,DC=corp,DC=example'` | Resolved propagation ACEs | Windows |
| `certipy` | `certipy find -u lowpriv@corp.example -p pass -dc-ip 10.20.30.10 -stdout` | Certificate inventory for persistence artefacts | Linux / Windows |

## Minimal Lab Validation Script

Report the trust state for each persistence family; no mechanism is created or modified by this probe.

```python
from ldap3 import Server, Connection, NTLM
from datetime import datetime, timezone

srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=example", "(sAMAccountName=krbtgt)",
            attributes=["pwdLastSet", "msDS-KeyVersionNumber"])
for e in conn.entries:
    raw = e.pwdLastSet.value
    ts = (datetime.fromtimestamp(raw / 10_000_000 - 11644473600, tz=timezone.utc)
          if raw else None)
    print("krbtgt_last_set", ts, "key_version", e.msDS_KeyVersionNumber.value)

conn.search("DC=corp,DC=example", "(&(objectClass=user)(sIDHistory=*))",
            attributes=["sAMAccountName", "sIDHistory"])
for e in conn.entries:
    print("sidhistory", e.sAMAccountName, e.sIDHistory.value)
```

## Flag Notes

- `msDS-KeyVersionNumber` advances on each rotation, so the count is the rotation-completeness check.
- `/showobjmeta` proves the change reached every DC, which is what makes a double rotation effective.
- `Get-Acl` on AdminSDHolder reads the propagation source rather than the propagated copies.
