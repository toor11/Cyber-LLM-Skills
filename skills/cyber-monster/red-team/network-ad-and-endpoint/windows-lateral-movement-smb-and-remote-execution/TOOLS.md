# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-lateral-movement-smb-and-remote-execution`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `netexec` | `netexec smb 10.20.30.20 -u Administrator -H <hash> --shares --loggedon-users` | Rights and session inventory | Linux / Windows |
| `impacket-psexec` | `impacket-psexec corp.example/admin:pass@10.20.30.20 cmd.exe /c whoami` | Service-based execution, lab only | Linux / Windows |
| `impacket-smbexec` | `impacket-smbexec -service svcname -file cmd.bat corp.example/admin:pass@10.20.30.20` | Service creation with an explicit binary, lab only | Linux / Windows |
| `smbclient` | `smbclient //10.20.30.20/ADMIN$ -U 'user%pass' -c 'ls'` | Admin share listing | Linux |
| `schtasks` | `schtasks /create /s 10.20.30.20 /tn t /tr cmd.exe /sc once /st 23:59 /u user /p pass` | Remote task creation, lab only | Windows |

## Minimal Lab Validation Script

Prove rights with a read-only admin share listing; service creation is a separate, separately authorised step.

```python
import subprocess

def admin_share_visible(host, user, password):
    cmd = ["smbclient", f"//{host}/ADMIN$", "-U", f"{user}%{password}", "-c", "ls"]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return res.returncode == 0, (res.stdout or res.stderr).strip().splitlines()[:3]

for host in ("10.20.30.20",):
    ok, head = admin_share_visible(host, "CORP/Administrator", "pass")
    print(host, "admin_share_readable", ok, head)
```

## Flag Notes

- `--loggedon-users` shows who is on the target, which is the session information that matters for impact.
- `-service` names the temporary service explicitly so cleanup can target it by name.
- `-c 'ls'` is a read, not a write; it proves the rights without modifying the target.
