# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`host-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `autorunsc` | `autorunsc.exe -accepteula -a * -h -s -nobanner` | Signed autostart inventory across all surfaces | Windows |
| `Get-ScheduledTask` | `Get-ScheduledTask &#124; Select-Object TaskName,TaskPath,Author` | Task population with author | Windows |
| `systemctl` | `systemctl list-unit-files --state=enabled` | Enabled units on Linux | Linux |
| `launchctl` | `launchctl list` | Loaded launchd jobs on macOS | macOS |
| `pkgutil` | `pkgutil --file-info /Library/LaunchDaemons/x.plist` | Package provenance on macOS | macOS |

## Minimal Lab Validation Script

Diff the autostart population against a reference image, which turns a large list into a small candidate set.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout

run_keys = ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run').PSObject.Properties | "
              "Where-Object { $_.Name -notlike 'PS*' } | Select-Object Name,Value | ConvertTo-Csv -NoTypeInformation")
tasks = ps("(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' }).Count")
services = ps("(Get-CimInstance Win32_Service | Where-Object { $_.PathName -notlike '*System32*' }).Count")

print("run_key_entries", len(run_keys.splitlines()) - 1)
print("non_microsoft_tasks", tasks.strip())
print("non_system32_services", services.strip())
```

## Flag Notes

- `-a *` in autorunsc covers every autostart category; narrowing it hides surfaces.
- `-h -s` adds file hashes and signature verification, which is what provenance needs.
- `--state=enabled` filters to units that actually start, which removes noise from installed-but-disabled units.
