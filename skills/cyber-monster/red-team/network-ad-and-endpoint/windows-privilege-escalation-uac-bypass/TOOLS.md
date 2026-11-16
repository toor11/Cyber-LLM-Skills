# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-privilege-escalation-uac-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `whoami` | `whoami /groups` | Integrity level and group filtering | Windows |
| `reg query` | `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | UAC policy values | Windows |
| `sigcheck` | `sigcheck.exe -m <binary>` | Manifest and auto-elevate flag | Windows |
| `UACME` | `Akagi64.exe <method> cmd.exe` | Bypass methods, authorised lab only | Windows |
| `Process Explorer` | Integrity column | Parent and child integrity comparison | Windows |

## Minimal Lab Validation Script

Report the policy values and the binary's auto-elevate flag; the bypass itself is a separate authorised step.

```python
import subprocess

KEYS = ["ConsentPromptBehaviorAdmin", "EnableLUA", "FilterAdministratorToken",
        "PromptOnSecureDesktop"]
ps = ("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
      "| Select-Object " + ",".join(KEYS) + " | ConvertTo-Json -Compress")
print(subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                     capture_output=True, text=True).stdout)
print(subprocess.run("whoami /groups", capture_output=True, text=True,
                     shell=True).stdout.split("Mandatory Label")[-1][:80])
```

## Flag Notes

- `-m` in sigcheck prints the manifest, which is where `autoElevate` appears.
- `/groups` filtered output shows the deny-only Administrators group, the mark of a filtered token.
- `PromptOnSecureDesktop` matters for whether a prompt can be spoofed, which is a separate finding.
