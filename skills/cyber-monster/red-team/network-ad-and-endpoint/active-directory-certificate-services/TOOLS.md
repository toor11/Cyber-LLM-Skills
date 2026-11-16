# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-certificate-services`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `certipy` | `certipy find -u lowpriv@corp.example -p pass -dc-ip 10.20.30.10 -vulnerable -stdout` | Read-only CA and template audit | Linux / Windows |
| `Certify` | `Certify.exe find /vulnerable` | Template audit from a Windows host | Windows |
| `certutil` | `certutil -getreg policy\DisableExtensionList` | CA policy module configuration | Windows |
| `Get-ADObject` | `Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp' -Filter * -Properties *` | Template attributes directly | Windows |
| `PSPKI` | `Get-CertificationAuthority &#124; Get-CATemplate` | Published template list per CA | Windows |

## Minimal Lab Validation Script

Classify each published template into an ESC class from its attributes, so the report names a specific class rather than a generic misconfiguration.

```python
from ldap3 import Server, Connection, NTLM

BASE = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example"
SUPPLY_SUBJECT = 0x1
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search(BASE, "(objectClass=pKICertificateTemplate)",
            attributes=["cn", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage",
                        "msPKI-Template-Schema-Version", "msPKI-Enrollment-Flag"])
for e in conn.entries:
    name_flag = int(e.msPKI_Certificate_Name_Flag.value or 0)
    eku = e.pKIExtendedKeyUsage.value or []
    supply = bool(name_flag & SUPPLY_SUBJECT)
    client = CLIENT_AUTH in eku or "2.5.29.37.0" in eku
    print(e.cn, "supply_subject", supply, "client_auth", client,
          "schema", e.msPKI_Template_Schema_Version.value)
```

## Flag Notes

- `-vulnerable` narrows output to templates that meet a known ESC condition; without it the report is unreadable.
- `-getreg policy\\DisableExtensionList` is the only direct read of the ESC16 condition.
- `-stdout` keeps the audit output reviewable instead of writing files across the working directory.
