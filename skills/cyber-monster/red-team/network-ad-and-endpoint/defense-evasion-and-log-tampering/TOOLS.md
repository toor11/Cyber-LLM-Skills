# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`defense-evasion-and-log-tampering`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `wevtutil` | `wevtutil gli Security` | Channel size, retention and record count | Windows |
| `auditpol` | `auditpol /get /category:*` | Effective audit subcategories | Windows |
| `Get-WinEvent` | `Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102}` | Clearing events | Windows |
| `EvtxECmd` | `EvtxECmd.exe -f Security.evtx --csv out` | Offline parsing with record-id continuity | Windows |
| `chainsaw` | `chainsaw hunt evtx/ -s sigma/` | Bulk EVTX triage against sigma rules | Cross-platform |

## Minimal Lab Validation Script

Report channel integrity state and the tampering events present; no log is modified by this probe.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("security_channel", ps("wevtutil gli Security"))
print("clearing_events", ps("(Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} "
                            "-MaxEvents 5 -ErrorAction SilentlyContinue).Count") or "0")
print("policy_changes", ps("(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4719} "
                            "-MaxEvents 5 -ErrorAction SilentlyContinue).Count") or "0")
print("audit_categories_enabled", ps("(auditpol /get /category:* | Select-String 'Success and Failure').Count"))
```

## Flag Notes

- `gli` reports channel size, retention mode and record count, which is the retention baseline.
- Counting 1102 and 4719 events establishes whether tampering is being recorded at all.
- `auditpol /get` shows the effective policy, which is what a remediation plan must change.
