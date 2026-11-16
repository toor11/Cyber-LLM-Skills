# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`host-persistence-registry-and-service-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `autorunsc` | `autorunsc.exe -a r,s,c -h -s -accepteula -nobanner` | Run keys, services and COM autostart with signatures | Windows |
| `reg query` | `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /s` | Autostart values | Windows |
| `Get-Acl` | `Get-Acl 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'` | Autostart key ACL | Windows |
| `sigcheck` | `sigcheck.exe -a -h -e <path>` | Signature and hash of the target binary | Windows |
| `Get-CimInstance` | `Get-CimInstance Win32_Service &#124; Select-Object Name,PathName,StartMode` | Service binary paths | Windows |

## Minimal Lab Validation Script

Pair each autostart value with its target's signature and the key's ACL, which is the whole finding in one view.

```python
import subprocess

KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
]
for key in KEYS:
    out = subprocess.run(["reg", "query", key], capture_output=True, text=True).stdout
    entries = [ln.strip() for ln in out.splitlines() if "REG_" in ln]
    print(key, "entries", len(entries))
    for entry in entries[:5]:
        print("  ", entry[:120])
```

## Flag Notes

- `-a r,s,c` restricts autorunsc to run keys, services and COM, which keeps the output reviewable.
- `-h -s` adds hashes and signature checks, which is the provenance evidence.
- `-e` in sigcheck scans a whole directory with signature output.
