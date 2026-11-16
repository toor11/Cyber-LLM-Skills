# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`lolbins-and-signed-binary-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `LOLBAS` | Search the project by binary name | Documented capabilities per signed binary | Cross-platform |
| `autorunsc` | `autorunsc.exe -a * -h -s` | Autostart entries referencing these binaries | Windows |
| `Get-CIPolicy` | `Get-CIPolicy -FilePath policy.xml` | Application control rules and mode | Windows |
| `sigcheck` | `sigcheck.exe -a -h -e <dir>` | Signature validation across a directory | Windows |
| `Get-WinEvent` | Filter Sysmon event 1 on the binary name | Command-line evidence | Windows |

## Minimal Lab Validation Script

Read the policy state and the invocation baseline; running a LOLBin is a separate authorised step.

```python
import subprocess

BINS = ("mshta", "rundll32", "regsvr32", "certutil", "installutil", "msbuild")
ps = ("Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} "
      "-MaxEvents 300 | Select-Object -ExpandProperty Message")
out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                     capture_output=True, text=True).stdout

for bin_name in BINS:
    hits = [ln for ln in out.splitlines() if bin_name in ln.lower()]
    if hits:
        print(bin_name, len(hits), hits[0][:140])
```

## Flag Notes

- Searching by binary name in Sysmon event 1 gives the command line, which is the discriminating evidence.
- `-a -h -s` in sigcheck adds hash and signature, needed when the binary is copied outside `System32`.
- The `RunMRU` key holds the most recent Run-dialog commands, which is where an instruction-based lure leaves evidence.
