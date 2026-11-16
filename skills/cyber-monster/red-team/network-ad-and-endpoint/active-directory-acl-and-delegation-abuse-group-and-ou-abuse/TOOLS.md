# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `PowerView` | `Get-DomainObjectAcl -ResolveGUIDs -SearchBase 'OU=Groups,DC=corp,DC=example'` | ACLs across a container | Windows |
| `net group` | `net group 'Domain Admins' /domain` | Current membership, non-destructive read | Windows |
| `bloodhound-python` | `bloodhound-python -c ACL,Group -d corp.example -u lowpriv -p pass -ns 10.20.30.10 --zip` | Group and ACL edges together | Linux / Windows |
| `Get-ADGroupMember` | `Get-ADGroupMember 'Server Admins' -Recursive` | Transitive membership | Windows |
| `AdFind` | `AdFind -b OU=Groups,DC=corp,DC=example -f '(&(objectClass=group))' member` | Direct member attribute per group | Windows |

## Minimal Lab Validation Script

Resolve transitive membership and container contents, so a group or OU finding names the objects it actually reaches.

```python
from ldap3 import Server, Connection, NTLM, SUBTREE
from ldap3.extend.microsoft.getADUser import getADUser  # noqa: F401

srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)

def members(dn, seen=None):
    seen = seen or set()
    conn.search(dn, "(objectClass=*)", search_scope="BASE", attributes=["member"])
    for e in conn.entries:
        for m in e.member or []:
            if m in seen:
                continue
            seen.add(m)
            conn.search(m, "(objectClass=*)", search_scope="BASE",
                        attributes=["objectClass", "sAMAccountName"])
            for obj in conn.entries:
                print(" ", m, obj.sAMAccountName)
                if "group" in [c.lower() for c in obj.objectClass or []]:
                    members(m, seen)

members("CN=Server Admins,OU=Groups,DC=corp,DC=example")
```

## Flag Notes

- `-Recursive` resolves nested membership, which is the only view that matches effective access.
- `-SearchBase` scopes ACL collection to a container, keeping output reviewable.
- `-filter` with `member` returns only the attribute that matters for group reachability.
