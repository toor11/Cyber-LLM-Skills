# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`initial-access-via-phishing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dig` | `dig +short TXT _dmarc.example.com` | DMARC policy for the sending domain | Cross-platform |
| `Get-TransportRule` | `Get-TransportRule &#124; Select-Object Name,State,Description` | Gateway rules that could quarantine | Windows |
| `Get-Item -Stream` | `Get-Item file.docm -Stream Zone.Identifier` | Mark-of-the-web presence | Windows |
| `urlscan` | Submit the lure URL to a sandboxed scanner | Landing page and redirect chain | Cross-platform |
| `Get-MpPreference` | `Get-MpPreference &#124; Select-Object *` | Endpoint execution and attachment policy | Windows |

## Minimal Lab Validation Script

Record the authentication result, the attachment's zone state and the user action required, which is the reproducible part of a phishing assessment.

```python
import subprocess

def dns(name, rtype):
    return subprocess.run(["dig", "+short", rtype, name], capture_output=True, text=True).stdout.strip()

for domain in ("example.com",):
    print(domain, "dmarc", dns(f"_dmarc.{domain}", "TXT"))
    print(domain, "spf", dns(domain, "TXT")[:200])
print("motw", subprocess.run(
    ["powershell", "-NoProfile", "-Command",
     "(Get-Item .\\invoice.docm -Stream Zone.Identifier -ErrorAction SilentlyContinue).Stream"],
    capture_output=True, text=True).stdout.strip() or "absent")
```

## Flag Notes

- `+short` keeps DNS output to the record value, which is what a report needs.
- `-Stream Zone.Identifier` reads the alternate data stream that carries the mark of the web.
- `DisableBlockAtFirstSeen` false is the hardened setting for unknown attachments.
