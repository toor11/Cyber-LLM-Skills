# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`lolbins-and-signed-binary-abuse-execution-proxies`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `LOLBAS` | Look up the binary and argument pairing | Documented proxy capability | Cross-platform |
| `Get-WinEvent` | Sysmon event 1 filtered on the binary name | Command line and parent process | Windows |
| `sigcheck` | `sigcheck.exe -a -h <file>` | Provenance of the proxied content | Windows |
| `Get-CIPolicy` | `Get-CIPolicy -FilePath policy.xml` | Rule set and enforcement mode | Windows |
| `Process Explorer` | Process tree with command line column | Parent-child relationship | Windows |

## Minimal Lab Validation Script

Report proxy availability and the invocation baseline; executing a proxy is a separate authorised step.

```python
import subprocess

PAIRS = {"mshta": (".hta", "http"), "rundll32": (",#", "dll"), "regsvr32": ("scrobj.dll", "/i:")}
ps = ("Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} "
      "-MaxEvents 300 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Message")
out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                     capture_output=True, text=True).stdout

for binary, markers in PAIRS.items():
    hits = [ln for ln in out.splitlines() if binary in ln.lower()
            and any(m in ln.lower() for m in markers)]
    print(binary, "suspicious_invocations", len(hits), hits[:1])
```

## Flag Notes

- Filtering Sysmon event 1 by binary name and argument marker produces the candidate set without a full hunt.
- `3077` code integrity events prove the policy blocked an invocation, which is the control verification.
- `RunMRU` is where an instruction-based delivery leaves the pasted command, which is often the only record.
