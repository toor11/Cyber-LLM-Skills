# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-privilege-escalation-token-and-privilege-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `whoami` | `whoami /priv` | Privilege list with enabled state | Windows |
| `PrintSpoofer` / `GodPotato` | `PrintSpoofer.exe -i -c cmd` | Token acquisition from a local service, authorised lab only | Windows |
| `Seatbelt` | `Seatbelt.exe TokenPrivileges` | Structured privilege and policy output | Windows |
| `accesschk` | `accesschk.exe -p <pid>` | Process DACL and access | Windows |
| `Process Explorer` | Security tab of a process | Token groups and integrity for comparison | Windows |

## Minimal Lab Validation Script

Report the privilege state and available token sources; no token is acquired by this probe.

```python
import subprocess

SENSITIVE = ("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
             "SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
             "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege")

out = subprocess.run("whoami /priv", capture_output=True, text=True, shell=True).stdout
for line in out.splitlines():
    for priv in SENSITIVE:
        if priv in line:
            print(priv, "enabled" if "Enabled" in line else "held-not-enabled")
```

## Flag Notes

- `-i` in PrintSpoofer requests an interactive shell from the acquired token; lab use only.
- `TokenPrivileges` in Seatbelt produces machine-readable output for comparison across hosts.
- `-p` in accesschk scopes to one process rather than the whole object namespace.
