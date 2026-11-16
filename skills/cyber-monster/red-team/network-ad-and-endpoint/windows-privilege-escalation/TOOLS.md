# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-privilege-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `winPEAS` | `winPEASx64.exe quiet cmd` | Consolidated boundary inventory | Windows |
| `accesschk` | `accesschk.exe -quvwc "Users" C:\` | Writable directories by principal | Windows |
| `PowerUp` | `Invoke-AllChecks` | Service, path and policy checks | Windows |
| `sc.exe` | `sc.exe qc SvcApp` | Service binary path and account | Windows |
| `icacls` | `icacls 'C:\ProgramData\Vendor'` | Directory ACL | Windows |

## Minimal Lab Validation Script

Produce a boundary inventory with the object state that permits each crossing, which is the only part of the assessment that can be remediated.

```python
import subprocess

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout

def writable_dirs_for_users(root):
    out = run(f'icacls "{root}"')
    return [ln.strip() for ln in out.splitlines()
            if ("BUILTIN\\Users" in ln or "Everyone" in ln) and "(F)" in ln]

services = run('powershell -NoProfile -Command "Get-CimInstance Win32_Service | '
               'Select-Object -ExpandProperty PathName"')
for path in services.splitlines():
    path = path.strip().strip('"')
    parent = path.rsplit("\\", 1)[0] if "\\" in path else path
    hits = writable_dirs_for_users(parent) if parent else []
    if hits:
        print("writable-service-parent", parent, hits[:1])
```

## Flag Notes

- `quiet cmd` in winPEAS reduces console noise and keeps output reviewable.
- `-quvwc` filters accesschk to writable objects for a principal, which produces the actionable list.
- `Invoke-AllChecks` in PowerUp reports findings without changing state, unlike the exploitation functions.
