# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-privilege-escalation-credential-and-config-exposure`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-ChildItem` | `Get-ChildItem C:\Windows\Panther -Filter 'unattend*' -Recurse` | Locate imaging artefacts | Windows |
| `icacls` | `icacls C:\Windows\Panther\unattend.xml` | Prove readability | Windows |
| `reg query` | `reg query HKLM\SYSTEM\CurrentControlSet\Services /s /f Password` | Service password values | Windows |
| `Seatbelt` | `Seatbelt.exe InterestingFiles` | Structured credential-file inventory | Windows |
| `netexec` | `netexec smb dc01 -u lowpriv -p pass -M gpp_password` | GPP credential discovery over SYSVOL | Linux / Windows |

## Minimal Lab Validation Script

Report the exposure and the account state; decoding or using a recovered secret is a separate authorised step.

```python
import os, re, subprocess

CANDIDATES = [
    r"C:\Windows\Panther\unattend.xml",
    r"C:\Windows\System32\Sysprep\unattend.xml",
    r"C:\Windows\Panther\Unattend\Unattend.xml",
]
for path in CANDIDATES:
    if not os.path.exists(path):
        continue
    acl = subprocess.run(["icacls", path], capture_output=True, text=True).stdout
    body = open(path, encoding="utf-8", errors="ignore").read()
    has_pw = bool(re.search(r"<Password>", body, re.I))
    broad = "BUILTIN\\Users" in acl or "Everyone" in acl
    print(path, "password_element", has_pw, "broad_read", broad)
```

## Flag Notes

- `-Recurse` is needed because Panther can hold nested imaging folders.
- `/s /f Password` searches the whole service tree for a value name, which is faster than enumerating each key.
- `-M gpp_password` reads SYSVOL policy files without writing anything.
