# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-privilege-escalation-service-and-path-flaws`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sc.exe` | `sc.exe qc LegacyAgent` | Binary path, account and start type | Windows |
| `sc.exe` | `sc.exe sdshow LegacyAgent` | Service DACL in SDDL | Windows |
| `accesschk` | `accesschk.exe -quvwc "Users" C:\` | Writable directories for a principal | Windows |
| `icacls` | `icacls 'C:\Program Files\Legacy'` | Directory ACL | Windows |
| `PowerUp` | `Get-ServiceUnquoted`, `Get-ModifiableService` | Path and DACL checks without exploitation | Windows |

## Minimal Lab Validation Script

Classify each automatic service by path quoting, parent-directory ACL and DACL, which produces a ranked, remediable list.

```python
import subprocess

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout

raw = run('powershell -NoProfile -Command "Get-CimInstance Win32_Service | '
          'Where-Object {$_.StartMode -eq \'Auto\'} | '
          'Select-Object Name,PathName | ConvertTo-Csv -NoTypeInformation"')
for line in raw.splitlines()[1:]:
    parts = [p.strip('"') for p in line.split('","')]
    if len(parts) != 2:
        continue
    name, path = parts
    unquoted = not path.startswith('"') and " " in path
    parent = path.strip('"').rsplit("\\", 1)[0] if "\\" in path else ""
    if unquoted:
        print("unquoted", name, path)
    if parent:
        acl = run(f'icacls "{parent}"')
        if "BUILTIN\\Users" in acl or "Everyone" in acl:
            print("broad-acl-parent", name, parent)
```

## Flag Notes

- `qc` prints the stored path exactly as the SCM holds it, which is what determines parsing.
- `sdshow` output can be fed back to `sdset` after removing the offending ACE, which is the remediation path.
- `-quvwc` restricts accesschk output to write-capable ACEs for the named principal.
