# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`host-persistence-linux-and-macos-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `systemctl` | `systemctl list-unit-files --state=enabled` | Enabled boot-time units | Linux |
| `launchctl` | `launchctl list` | Loaded launchd jobs | macOS |
| `pkgutil` | `pkgutil --file-info /Library/LaunchDaemons/x.plist` | Package provenance on macOS | macOS |
| `dpkg` | `dpkg -S /etc/systemd/system/myunit.service` | Package provenance on Linux | Linux |
| `find` | `find /etc/systemd/system -newer /etc/hostname -type f` | Recently added units | Linux |

## Minimal Lab Validation Script

Report configuration entries with no package provenance and the permissions of the paths they load.

```python
import os, subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

units = [p for p in run("systemctl list-unit-files --state=enabled --no-legend").splitlines()]
print("enabled_units", len(units))
for line in units[:10]:
    name = line.split()[0]
    path = f"/etc/systemd/system/{name}"
    if os.path.exists(path):
        owned = run(f"dpkg -S {path} 2>/dev/null").strip()
        print("  ", name, "packaged" if owned else "UNPACKAGED")

print("ld_preload", os.path.exists("/etc/ld.so.preload"),
      run("cat /etc/ld.so.preload 2>/dev/null").strip()[:120])
```

## Flag Notes

- `--no-legend` removes the header so the output can be counted directly.
- `--file-info` reports the installing package for a path, which is the provenance check on macOS.
- `-newer` finds units changed since a reference file, which is the fastest way to spot an addition.
