# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-enumeration-gpo-and-administrative-discovery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-GPOReport` | `Get-GPOReport -All -ReportType Xml -Path gpo.xml` | Effective settings for every GPO | Windows |
| `netexec` | `netexec ldap dc -u user -p pass --query '(objectClass=groupPolicyContainer)' displayName` | GPO object inventory over LDAP | Linux / Windows |
| `gpresult` | `gpresult /h report.html /scope computer` | Applied policy on one host, which proves effect | Windows |
| `PowerView` | `Get-DomainGPO -Domain corp.example &#124; Select-Object displayname,gpcfilesyspath` | GPO and SYSVOL path mapping | Windows |
| `smbclient` | `smbclient //dc01/SYSVOL -c 'recurse ON; ls Policies'` | SYSVOL content read with an identity | Linux |

## Minimal Lab Validation Script

Read GPO linkage and container ACLs together, so a policy finding always carries the writable path that makes it reachable.

```python
from ldap3 import Server, Connection, NTLM
from ldap3.protocol.microsoft import security_descriptor_control

srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("CN=Policies,CN=System,DC=corp,DC=example", "(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath", "nTSecurityDescriptor"],
            controls=security_descriptor_control(sdflags=0x04))
for e in conn.entries:
    print(e.displayName, e.gPCFileSysPath)
```

## Flag Notes

- `-ReportType Xml` gives parseable output, which is what makes a diff between two collection dates meaningful.
- `/scope computer` separates computer from user policy, which loopback processing makes non-interchangeable.
- `gPCFileSysPath` ties the directory object to the SYSVOL folder whose ACL also grants edit rights.
