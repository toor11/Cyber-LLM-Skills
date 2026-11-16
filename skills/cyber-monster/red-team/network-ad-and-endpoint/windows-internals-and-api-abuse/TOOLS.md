# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-internals-and-api-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `whoami` | `whoami /all` | Token, privileges, groups, integrity | Windows |
| `sc.exe` | `sc.exe sdshow SvcApp` | Service object DACL | Windows |
| `accesschk` | `accesschk.exe -quvwc "Everyone" *` | Find objects writable by a broad group | Windows |
| `handle` | `handle.exe -a -p <pid>` | Handles held by a process | Windows |
| `Process Explorer` | Process properties, Security tab | Token and integrity in a GUI | Windows |

## Minimal Lab Validation Script

Snapshot the token and the object DACL for one target, so a later change is attributable to one control.

```python
import subprocess

def run(cmd):
    out = subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
    return [ln.strip() for ln in out.splitlines() if ln.strip()]

print("PRIVILEGES")
for line in run("whoami /priv"):
    if "Enabled" in line or "Privilege Name" in line:
        print("  ", line)

print("SERVICE DACL")
for line in run("sc.exe sdshow SvcApp")[:3]:
    print("  ", line)
```

## Flag Notes

- `/all` adds groups, privileges and integrity in one read; `/priv` alone hides the integrity level.
- `-quvwc` in accesschk filters to writable objects for a named principal, which is the actionable set.
- `sc sdshow` prints SDDL, which is the only format that preserves the ACE list exactly.
