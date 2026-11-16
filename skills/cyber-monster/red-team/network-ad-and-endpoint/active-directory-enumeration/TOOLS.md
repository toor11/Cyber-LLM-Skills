# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `bloodhound-python` | `bloodhound-python -d corp.example -u lowpriv -p pass -ns 10.20.30.10 -c All --zip` | Edge collection with a named identity | Linux / Windows |
| `netexec` | `netexec ldap 10.20.30.10 -u lowpriv -p pass --bloodhound -c All` | Collection over LDAP from one host | Linux / Windows |
| `ldapsearch` | `ldapsearch -x -H ldap://dc01 -D user@corp -W -b 'DC=corp,DC=example' '(objectClass=group)' member` | Direct attribute read, no graph layer | Linux / macOS |
| `Get-ADObject` | `Get-ADObject -Filter * -SearchBase 'OU=Servers,DC=corp,DC=example' -Properties *` | Object view with all readable attributes | Windows |
| `SharpHound` | `SharpHound.exe -c All --ZipFileName corp.zip` | Collection from a Windows domain host | Windows |

## Minimal Lab Validation Script

Read a security descriptor for one object and print the trustee, mask and inheritance, so an edge claim cites the ACL rather than a graph edge.

```python
from ldap3 import Server, Connection, NTLM, ALL
from ldap3.protocol.microsoft import security_descriptor_control

srv = Server("10.20.30.10", get_info=ALL)
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
ctrl = security_descriptor_control(sdflags=0x04)  # DACL only
conn.search("DC=corp,DC=example", "(sAMAccountName=svc_sql)",
            attributes=["nTSecurityDescriptor", "msDS-ManagedPassword"], controls=ctrl)
for entry in conn.entries:
    print(entry.entry_dn, entry.nTSecurityDescriptor.raw_values)
```

## Flag Notes

- `-c All` collects every method; narrowing to `ACL,Trusts` produces a smaller and less noisy dataset.
- `--zip` keeps collectors from writing dozens of JSON files into the working directory.
- `sdflags=0x04` requests only the DACL, which is the part that proves a permission.
