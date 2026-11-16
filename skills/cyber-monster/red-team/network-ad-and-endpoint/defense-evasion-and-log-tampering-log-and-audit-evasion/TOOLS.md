# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`defense-evasion-and-log-tampering-log-and-audit-evasion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `auditpol` | `auditpol /get /category:*` | Effective audit subcategories | Windows |
| `wevtutil` | `wevtutil gl Security` | Channel enablement and retention | Windows |
| `Get-Acl` | `(Get-Acl 'AD:DC=corp,DC=example').Audit` | Object SACL entries | Windows |
| `Get-WinEvent` | Filter event 4719 | Policy change records | Windows |
| `secedit` | `secedit /export /cfg audit.inf` | Local security policy export for comparison | Windows |

## Minimal Lab Validation Script

Report the effective policy and the SACL state for the objects the control depends on.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("policy_change", ps("(auditpol /get /subcategory:'Audit Policy Change') -join ' '"))
print("process_creation", ps("(auditpol /get /subcategory:'Process Creation') -join ' '"))
print("cmdline_flag", ps("(Get-ItemProperty "
                         "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' "
                         "-ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled") or "unset")
print("4719_count", ps("(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4719} "
                       "-MaxEvents 50 -ErrorAction SilentlyContinue).Count") or "0")
```

## Flag Notes

- `/subcategory` targets one category, which is the only reliable way to read its state.
- `/export` writes a comparable configuration file for diffing against a baseline.
- The command-line inclusion flag is a registry value, not an auditpol setting, so both reads are needed.
