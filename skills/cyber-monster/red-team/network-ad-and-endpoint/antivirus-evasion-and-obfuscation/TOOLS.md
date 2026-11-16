# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`antivirus-evasion-and-obfuscation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-MpPreference` | `Get-MpPreference &#124; Select-Object *` | ASR, cloud protection and exclusion state | Windows |
| `Get-WinEvent` | PowerShell operational log, event 4104 | Decoded script text | Windows |
| `Get-MpComputerStatus` | `Get-MpComputerStatus` | Real-time and tamper-protection state | Windows |
| `AMSI test` | Registered provider list under `HKLM\SOFTWARE\Microsoft\AMSI\Providers` | Script scanning providers | Windows |
| `Sysmon` | Event 1 filtered on `-EncodedCommand` | Encoded launch pattern | Windows |

## Minimal Lab Validation Script

Report the instrumentation state and the decoded-text evidence; no malicious content is used to test a control.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("script_block_logging", ps(
    "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
    "-ErrorAction SilentlyContinue).EnableScriptBlockLogging") or "unset")
print("asr_rules", ps("(Get-MpPreference).AttackSurfaceReductionRules_Ids -join ','")[:200])
print("amsi_providers", ps(
    "(Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers' -ErrorAction SilentlyContinue).PSChildName -join ','"))
print("tamper_protection", ps("(Get-MpComputerStatus).IsTamperProtected"))
```

## Flag Notes

- `IsTamperProtected` indicates whether a local administrator can disable the control, which is the evasion precondition.
- ASR rule ids paired with actions distinguish audit from block, which is what a remediation plan needs.
- The AMSI provider list being empty means script content is not inspected at all.
