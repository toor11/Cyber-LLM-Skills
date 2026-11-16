# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-Process` | `Get-Process &#124; Select-Object Name,ProtectionLevel` | Process protection state | Windows |
| `Process Explorer` | Strings tab / memory view of a module | In-memory versus on-disk comparison | Windows |
| `dumpbin` | `dumpbin /disasm ntdll.dll` | On-disk function bytes | Windows |
| `Sysmon` | Event 10 filtered on self-access | In-memory modification attempt | Windows |
| `Get-CimInstance Win32_DeviceGuard` | DeviceGuard namespace | HVCI and VBS, which protect kernel callbacks | Windows |

## Minimal Lab Validation Script

Report hook state and process protection; no memory is modified by this probe.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

for name in ("lsass", "edragent", "MsMpEng"):
    print(name, ps(f"(Get-Process -Name {name} -ErrorAction SilentlyContinue).ProtectionLevel") or "not-running")
print("hvci", ps("(Get-CimInstance -ClassName Win32_DeviceGuard "
                 "-Namespace root\\Microsoft\\Windows\\DeviceGuard).SecurityServicesRunning"))
print("sysmon_10_self", ps("(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} "
                           "-MaxEvents 100 -ErrorAction SilentlyContinue | "
                           "Where-Object { $_.Message -match 'SourceImage.*TargetImage' }).Count") or "0")
```

## Flag Notes

- `ProtectionLevel` is empty for unprotected processes and `PsProtectedSigner...` for protected ones.
- Comparing in-memory bytes to the on-disk DLL is the only way to prove a hook's presence or removal.
- HVCI and VBS make kernel callback removal harder, so their state bounds the technique.
