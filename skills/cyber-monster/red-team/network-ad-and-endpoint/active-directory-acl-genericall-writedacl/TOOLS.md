# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-acl-genericall-writedacl`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dacledit.py` | `dacledit.py -action read -target adm_target -principal lowpriv corp.example/lowpriv:pass -dc-ip 10.20.30.10` | Read DACL with a given principal | Linux / Windows |
| `PowerView` | `Get-DomainObjectAcl -ResolveGUIDs -Identity 'Domain Admins'` | Resolved ACEs on a group | Windows |
| `Get-Acl` | `Get-Acl 'AD:CN=Domain Admins,CN=Users,DC=corp,DC=example'` | Native descriptor view | Windows |
| `bloodhound-python` | `bloodhound-python -c ACL -d corp.example -u lowpriv -p pass -ns 10.20.30.10 --zip` | ACL edge collection | Linux / Windows |
| `AdFind` | `AdFind -b DC=corp,DC=example -sddl++ -sddlfilter ;rights=WRITE_DAC;;;` | Filter objects by a specific right in SDDL | Windows |

## Minimal Lab Validation Script

Compute effective rights for one trustee on one object by walking the DACL in order, which is the only correct way to read a deny.

```python
from ldap3 import Server, Connection, NTLM
from ldap3.protocol.microsoft import security_descriptor_control

TARGET = "CN=Domain Admins,CN=Users,DC=corp,DC=example"
WATCH = 0x40000 | 0x80000 | 0xF01FF
srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=example", "(distinguishedName=%s)" % TARGET,
            attributes=["nTSecurityDescriptor"],
            controls=security_descriptor_control(sdflags=0x04))
for e in conn.entries:
    sd = e.nTSecurityDescriptor.value
    for ace in sd["dacl"].aces or []:
        mask = int(ace["access_mask"])
        if mask & WATCH:
            print(ace.get("ace_type"), ace.get("trustee"), hex(mask))
```

## Flag Notes

- `-action read` performs no modification; the write actions are a remediation step, not an assessment step.
- `-sddl++` emits full SDDL, which is the only format that survives a copy into a report without losing the ACE type.
- `;rights=WRITE_DAC;;;` is an SDDL filter that finds objects by right rather than by trustee.
