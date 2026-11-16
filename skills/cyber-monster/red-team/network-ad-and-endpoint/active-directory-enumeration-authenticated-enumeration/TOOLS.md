# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-enumeration-authenticated-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `bloodhound-python` | `bloodhound-python -d corp.example -u lowpriv -p pass -ns 10.20.30.10 -c ACL,ObjectProps,Session --zip` | Edges with ACL and property context | Linux / Windows |
| `netexec` | `netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(objectClass=user)' msDS-KeyCredentialLink` | Direct LDAP attribute read | Linux / Windows |
| `Get-ADUser` | `Get-ADUser -Filter * -Properties servicePrincipalName,msDS-KeyCredentialLink` | Kerberoastable and shadow-credential state | Windows |
| `PowerView` | `Get-DomainObjectAcl -ResolveGUIDs -Identity adm_target` | Resolved ACEs for one object | Windows |
| `ldeep` | `ldeep ldap -s dc01 -d corp.example -u lowpriv -p pass search '(objectClass=computer)'` | LDAP search with a clean output format | Linux |

## Minimal Lab Validation Script

Read one object's DACL and print only ACEs that grant write-style rights to broad trustees, which is the set that produces escalation edges.

```python
from ldap3 import Server, Connection, NTLM, ALL
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.extend.microsoft import adPerson  # noqa: F401  (kept for parity with lab tooling)

WRITE_MASKS = {0x20, 0x40, 0x100, 0x40000, 0x10000000}
srv = Server("10.20.30.10", get_info=ALL)
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=example", "(sAMAccountName=adm_target)",
            attributes=["nTSecurityDescriptor"], controls=security_descriptor_control(sdflags=0x04))
for e in conn.entries:
    sd = e.nTSecurityDescriptor.value
    if sd is None:
        continue
    for ace in sd["dacl"].aces:
        if ace["access_mask"] & sum(WRITE_MASKS):
            print(e.entry_dn, ace[" trustee"] if False else ace.get("trustee"),
                  hex(ace["access_mask"]))
```

## Flag Notes

- `-c ACL,ObjectProps,Session` collects the three sources that produce usable edges without the full volume of `All`.
- `-ResolveGUIDs` turns schema GUIDs into readable right names, which is required to report an ACE meaningfully.
- `sdflags=0x04` fetches only the DACL, keeping the response small enough to parse reliably.
