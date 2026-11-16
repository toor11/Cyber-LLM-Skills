# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-acl-and-delegation-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `PowerView` | `Get-DomainObjectAcl -ResolveGUIDs -Identity adm_target` | Resolved ACEs for one object | Windows |
| `bloodhound-python` | `bloodhound-python -d corp.example -u lowpriv -p pass -ns 10.20.30.10 -c ACL --zip` | ACL edge collection | Linux / Windows |
| `netexec` | `netexec ldap dc -u user -p pass --query '(objectClass=*)' nTSecurityDescriptor` | Raw descriptor read over LDAP | Linux / Windows |
| `dacledit.py` | `dacledit.py -action read -target adm_target -principal lowpriv corp.example/lowpriv:pass -dc-ip 10.20.30.10` | Read a target DACL with a given principal | Linux / Windows |
| `Get-Acl` | `Get-Acl 'AD:CN=adm_target,OU=Privileged,DC=corp,DC=example'` | Windows-native descriptor view | Windows |

## Minimal Lab Validation Script

Report only ACEs that grant write-style rights to trustees that are not tier-0, which is the set that produces escalation edges.

```python
from ldap3 import Server, Connection, NTLM
from ldap3.protocol.microsoft import security_descriptor_control

WRITE_BITS = 0x20 | 0x40 | 0x100 | 0x40000 | 0x10000000 | 0x100
srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=example", "(sAMAccountName=adm_target)",
            attributes=["nTSecurityDescriptor"],
            controls=security_descriptor_control(sdflags=0x04))
for e in conn.entries:
    sd = e.nTSecurityDescriptor.value
    if not sd:
        continue
    for ace in sd["dacl"].aces:
        if int(ace["access_mask"]) & WRITE_BITS:
            print(e.entry_dn, ace.get("trustee"), hex(int(ace["access_mask"])),
                  ace.get("ace_type"))
```

## Flag Notes

- `-ResolveGUIDs` is mandatory to read a schema-GUID-scoped ACE meaningfully.
- `-action read` only reads the DACL; the write actions belong to an authorised change, not an assessment.
- `sdflags=0x04` limits the fetch to the DACL, which is the part that proves permission.
