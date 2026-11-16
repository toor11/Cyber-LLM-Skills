# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`macos-security-bypass-tcc-and-privacy-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sqlite3` | `sqlite3 TCC.db 'select service,client,auth_value from access'` | Grant inventory, requires full disk access | macOS |
| `tccutil` | `tccutil reset SystemPolicyAllFiles <bundle-id>` | Reset a grant for one client | macOS |
| `codesign` | `codesign -dv --verbose=4 <app>` | Client code identity | macOS |
| `log` | `log show --predicate 'subsystem == "com.apple.TCC"'` | Grant and denial events | macOS |
| `system_profiler` | `system_profiler SPApplicationsDataType` | Installed application inventory with signatures | macOS |

## Minimal Lab Validation Script

Report the grant table and the client identities; editing the database is a high-impact change and is not part of this probe.

```python
import os, subprocess

db = os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
if os.path.exists(db):
    out = subprocess.run(["sqlite3", db,
                          "select service,client,auth_value from access"],
                         capture_output=True, text=True)
    print("grants", out.stdout.strip().splitlines()[:10] or out.stderr.strip()[:120])
else:
    print("tcc_db_unreadable_without_full_disk_access")
print("os_version", subprocess.run(["sw_vers", "-productVersion"],
                                   capture_output=True, text=True).stdout.strip())
```

## Flag Notes

- `sqlite3` on the TCC database fails without full disk access, which is itself a useful context signal.
- `tccutil reset` withdraws one client's grant, the least invasive remediation.
- `log show` with the TCC subsystem gives grant and denial events with the responsible process.
