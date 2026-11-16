# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`defense-evasion-and-log-tampering-indicator-removal`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `fsutil` | `fsutil usn readjournal C: csv` | USN journal with delete reason flags | Windows |
| `MFTECmd` | `MFTECmd.exe -f $MFT --csv out` | MFT records including deleted entries | Windows |
| `PECmd` | `PECmd.exe -d C:\Windows\Prefetch --csv out` | Prefetch inventory and timestamps | Windows |
| `AmcacheParser` | `AmcacheParser.exe -f Amcache.hve --csv out` | Execution history that survives deletion | Windows |
| `Get-WinEvent` | Event 4688 and 4699 filters | Execution and deletion records | Windows |

## Minimal Lab Validation Script

Compare expected artefacts against present ones for one execution, which is the reproducible part of an anti-forensics assessment.

```python
import os, subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

prefetch = ps("(Get-ChildItem C:\\Windows\\Prefetch -Filter *.pf -ErrorAction SilentlyContinue).Count")
exec_logged = ps("(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} "
                 "-MaxEvents 200 -ErrorAction SilentlyContinue).Count")
deleted_tasks = ps("(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4699} "
                   "-MaxEvents 20 -ErrorAction SilentlyContinue).Count")
print("prefetch_files", prefetch, "recent_4688", exec_logged, "deleted_tasks", deleted_tasks)
print("prefetch_enabled", ps("(Get-ItemProperty "
                             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters' "
                             "-ErrorAction SilentlyContinue).EnablePrefetch"))
```

## Flag Notes

- `usn readjournal C: csv` produces parseable output that can be filtered for the delete reason flag.
- `--csv` on the parsers keeps output reviewable and diffable across hosts.
- Counting prefetch files against logged executions reveals a mismatch, which is the differential.
