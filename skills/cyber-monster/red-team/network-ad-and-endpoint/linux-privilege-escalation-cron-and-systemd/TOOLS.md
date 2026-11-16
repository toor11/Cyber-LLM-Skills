# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`linux-privilege-escalation-cron-and-systemd`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `pspy` | `pspy64 -pf -i 1000` | Watch scheduled execution as an unprivileged user | Linux |
| `crontab` | `crontab -l -u root` | Root crontab, where permitted | Linux |
| `systemctl` | `systemctl list-timers --all` | Timer inventory with next run | Linux |
| `find` | `find /etc/cron* -writable` | Writable scheduling files | Linux |
| `ls` | `ls -l /etc/cron.d` | Ownership and mode of job files | Linux |

## Minimal Lab Validation Script

Pair each scheduling entry with the ownership of what it executes, so a job finding always names the writable element.

```python
import os, re, subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

writable = run("find /etc/cron* /var/spool/cron -writable 2>/dev/null").splitlines()
print("writable_schedule_files", writable[:10])

for job in run("grep -rhE '^[^#].*root' /etc/cron.d /etc/crontab 2>/dev/null").splitlines():
    parts = job.split()
    if not parts:
        continue
    target = parts[-1]
    if target.startswith("/") and os.path.exists(target):
        st = os.stat(target)
        if st.st_mode & 0o022:
            print("group_or_world_writable_target", target, oct(st.st_mode & 0o777))

print("system_timers", len(run("systemctl list-timers --all --no-pager").splitlines()))
```

## Flag Notes

- `-pf -i 1000` in pspy shows file events and process executions once a second, which reveals short-lived jobs.
- `list-timers --all` includes inactive timers, which is where a staged unit usually appears.
- `-ls` on find prints the mode and owner, so one command gives both the permission and the identity.
