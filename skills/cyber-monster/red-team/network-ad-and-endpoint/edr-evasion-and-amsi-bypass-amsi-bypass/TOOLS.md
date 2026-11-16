# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`edr-evasion-and-amsi-bypass-amsi-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-ChildItem` | `Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'` | Registered providers | Windows |
| `Get-Process -Module` | `Get-Process powershell -Module &#124; Where-Object ModuleName -eq 'amsi.dll'` | Loaded module path | Windows |
| `Get-WinEvent` | PowerShell operational 4104 | Decoded script text | Windows |
| `sigcheck` | `sigcheck.exe -a -h C:\Windows\System32\amsi.dll` | Integrity of the AMSI DLL | Windows |
| `Get-AuthenticodeSignature` | `Get-AuthenticodeSignature C:\Windows\System32\amsi.dll` | Signature state of the DLL | Windows |

## Minimal Lab Validation Script

Report provider registration and the module path in use; no memory tampering is performed.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("providers", ps("(Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers' "
                      "-ErrorAction SilentlyContinue).PSChildName -join ','") or "none")
print("amsi_module", ps("(Get-Process powershell -Module -ErrorAction SilentlyContinue | "
                        "Where-Object ModuleName -eq 'amsi.dll').FileName") or "not-loaded")
print("4104_count", ps("(Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' "
                       "-MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object Id -eq 4104).Count") or "0")
```

## Flag Notes

- `-Module` lists loaded modules with their full path, which is the search-order evidence.
- Counting 4104 events establishes whether script-block logging is active at all.
- sigcheck on `amsi.dll` verifies the System32 copy is the signed original.
