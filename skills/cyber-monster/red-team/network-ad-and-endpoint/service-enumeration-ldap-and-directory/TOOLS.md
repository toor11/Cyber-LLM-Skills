# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`service-enumeration-ldap-and-directory`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ldapsearch` | `ldapsearch -x -H ldap://dc01 -s base -b '' +` | Root DSE including operational attributes | Linux / macOS |
| `nmap` | `nmap -p 389,636,3268,3269 --script ldap-rootdse,ssl-cert dc01` | Directory discovery and TLS identity | Cross-platform |
| `netexec` | `netexec ldap dc01 -u user -p pass --query '(objectClass=group)' member` | Authenticated LDAP query with an identity | Linux / Windows |
| `openssl` | `openssl s_client -connect dc01:636 -showcerts </dev/null` | LDAPS certificate chain | Cross-platform |
| `ldp.exe` | `ldp.exe` connect to 389 with no credentials, base scope, empty DN | Windows-native root DSE view | Windows |

## Minimal Lab Validation Script

Read the root DSE and one scoped search, then stop; the script exists to make the anonymous boundary explicit, not to walk the directory.

```python
from ldap3 import Server, Connection, ANONYMOUS, BASE, LEVEL

srv = Server("10.20.30.10", get_info=None, port=389)
conn = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
conn.search("", "(objectClass=*)", search_scope=BASE,
            attributes=["namingContexts", "supportedControl", "supportedLDAPVersion"])
print("root_dse", conn.response)
conn.search("DC=corp,DC=example", "(objectClass=computer)", search_scope=LEVEL,
            attributes=["cn"], size_limit=5)
print("anonymous_computers", len(conn.response))
```

## Flag Notes

- `-s base -b ''` is the only request that reliably works before authentication.
- `size_limit=5` keeps an anonymous probe from becoming a directory dump.
- `-H ldap://` versus `ldaps://` selects the channel; a difference between them is a TLS finding.
