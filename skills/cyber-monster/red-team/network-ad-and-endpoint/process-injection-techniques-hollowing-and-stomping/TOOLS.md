# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`process-injection-techniques-hollowing-and-stomping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Sysmon` | Event 25 | Image tampering | Windows |
| `Get-FileHash` | `Get-FileHash <module> -Algorithm SHA256` | On-disk module hash | Windows |
| `Process Explorer` | Image and memory strings view | In-memory versus on-disk comparison | Windows |
| `Volatility` | `vol.py -f mem.raw windows.malfind` | Unbacked executable regions in a memory image | Cross-platform |
| `PE-Sieve` | `pe-sieve64.exe /pid <pid>` | Detect replaced and implanted modules | Windows |

## Minimal Lab Validation Script

Compare module hashes and flag unbacked threads; no process memory is modified by this probe.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

tamper = ps("(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=25} "
            "-MaxEvents 5 -ErrorAction SilentlyContinue).Count")
print("image_tamper_events", tamper or "0")

disk_hash = ps("(Get-FileHash C:\\Windows\\System32\\ntdll.dll -Algorithm SHA256).Hash")
print("ntdll_disk_hash", disk_hash)
print("modules_sample", ps("(Get-Process -Id $PID).Modules | "
                           "Select-Object -First 5 ModuleName | ConvertTo-Csv -NoTypeInformation")[:200])
```

## Flag Notes

- Event 25 requires Sysmon 12 or later and explicit configuration, so check both the version and the config.
- A memory-versus-disk hash comparison is the only file-independent integrity check.
- `malfind` in Volatility reports unbacked executable regions from a memory image, which is the offline equivalent.
