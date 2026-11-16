# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`process-injection-techniques-injection-via-callbacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `logman` | `logman query providers` | Available ETW providers including callback-related ones | Windows |
| `Volatility` | `vol.py -f mem.raw windows.malfind` | Unbacked executable regions in a memory image | Cross-platform |
| `PE-Sieve` | `pe-sieve64.exe /pid <pid>` | Implanted modules and shellcode in a live process | Windows |
| `Process Explorer` | Threads and stack view | Thread stacks for out-of-module frames | Windows |
| `Get-WinEvent -ListProvider` | `Get-WinEvent -ListProvider *` | Provider inventory | Windows |

## Minimal Lab Validation Script

Report which callback-adjacent telemetry exists; the mechanism itself needs memory analysis.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

providers = ps("logman query providers | Select-String -Pattern 'ThreadPool|Callback' | "
               "Select-Object -First 5")
print("callback_providers", providers or "none")
print("thread_counts", ps("Get-Process | Sort-Object -Property @{Expression={$_.Threads.Count}} "
                          "-Descending | Select-Object -First 5 Name,@{n='Threads';e={$_.Threads.Count}} | "
                          "ConvertTo-Csv -NoTypeInformation")[:250])
```

## Flag Notes

- `logman query providers` is the fastest way to see whether callback-related providers exist on the build.
- Thread counts well above the process type's norm are a weak but useful indicator of pool abuse.
- `/pid` in PE-Sieve scans one process, which is the least invasive live-memory check.
