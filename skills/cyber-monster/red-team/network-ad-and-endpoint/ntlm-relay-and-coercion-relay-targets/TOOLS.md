# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ntlm-relay-and-coercion-relay-targets`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `netexec` | `netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(objectClass=domain)' --module ldap-checker` | LDAP signing and channel-binding checks | Linux / Windows |
| `nmap` | `nmap -p 445 --script smb2-security-mode 10.20.30.0/24` | SMB signing state across a range | Cross-platform |
| `ntlmrelayx.py` | `ntlmrelayx.py -t ldaps://dc01 -smb2support --delegate-access` | LDAP relay that sets RBCD, authorised lab only | Linux |
| `reg query` | `reg query 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'` | Channel-binding and signing values | Windows |
| `ldapsearch` | `ldapsearch -x -H ldaps://dc01 -D user -w pass -b '' -s base` | Prove whether an unbound LDAPS bind is accepted | Linux |

## Minimal Lab Validation Script

Assemble the relay-target matrix from configuration reads, which is the whole finding for a hardening report.

```python
import subprocess

def smb_signing(host):
    out = subprocess.run(["nmap", "-p", "445", "--script", "smb2-security-mode", host],
                         capture_output=True, text=True).stdout
    return ("required" if "signing enabled and required" in out
            else "not-required" if "not required" in out else "unknown")

def ldap_binding(host):
    ps = ("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' "
          "-ErrorAction SilentlyContinue).LdapEnforceChannelBinding")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True).stdout.strip()
    return out or "0-or-unset"

for host in ("10.20.30.10", "10.20.30.20", "10.20.30.30"):
    print(host, "smb_signing", smb_signing(host), "ldap_channel_binding", ldap_binding(host))
```

## Flag Notes

- `--delegate-access` sets RBCD through a relayed LDAP session; it is a state change and belongs only in an authorised lab.
- `--module ldap-checker` reports signing and channel-binding state without relaying.
- `-p 445` keeps the signing check to SMB, so the result is not confused with LDAP state.
