# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`linux-privilege-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `linPEAS` | `linpeas.sh -a` | Consolidated artefact inventory | Linux |
| `sudo` | `sudo -l` | Effective sudo rules for the current user | Linux |
| `getcap` | `getcap -r / 2>/dev/null` | File capabilities across the filesystem | Linux |
| `find` | `find / -xdev -perm -4000 -type f` | Setuid binaries | Linux |
| `pspy` | `pspy64 -pf -i 1000` | Observe scheduled process execution without root | Linux |

## Minimal Lab Validation Script

Classify each artefact by whether the current user can influence an input it consumes, which is the only condition that makes it actionable.

```python
import os, subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

suid = [p for p in run("find / -xdev -perm -4000 -type f 2>/dev/null").splitlines() if p]
caps = [p for p in run("getcap -r / 2>/dev/null").splitlines() if p]
sudo = [ln for ln in run("sudo -l 2>/dev/null").splitlines() if "NOPASSWD" in ln or "(ALL" in ln]

print("suid_count", len(suid))
print("capabilities", caps[:10])
print("sudo_rules", sudo[:10])
print("writable_cron", run("find /etc/cron* -writable 2>/dev/null").splitlines()[:5])
```

## Flag Notes

- `-xdev` keeps the setuid search on one filesystem, which avoids crossing into network mounts.
- `-a` in linPEAS enables all checks; without it the output is a subset and may miss the artefact.
- `-pf -i 1000` in pspy watches process execution at one-second intervals as an unprivileged user.
