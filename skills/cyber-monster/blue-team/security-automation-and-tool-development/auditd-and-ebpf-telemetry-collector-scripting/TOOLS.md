# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`auditd-and-ebpf-telemetry-collector-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `auditctl --help` or `bpftrace --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Linux `auditd` (`auditctl` rules, `augenrules --load`, `ausearch`/`auparse` for reassembly) and `bpftrace` (`tracepoint:`/`kprobe:` probes, `@map` aggregation, `interval` probes)
- **Validation Gate:** `python -m py_compile audit_parse.py; bpftrace --dry-run probe.bt`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `auditctl` | `auditctl -a always,exit -F arch=b64 -S execve -k process_exec` | Add a syscall rule at runtime (lost on reboot) | Linux |
| `auditctl` | `auditctl -l` | List loaded rules; the authority on what is active | Linux |
| `auditctl` | `auditctl -s` | Report audit subsystem status and backlog | Linux |
| `augenrules` | `augenrules --load` | Compile `/etc/audit/rules.d/*.rules` into the active rule set | Linux |
| `ausearch` | `ausearch -k <key> -ts recent` / `ausearch -a <serial> -i` | Search by key, or reassemble one event by serial | Linux |
| `auparse` / `ausearch` | `ausearch -i` | Interpret numeric fields (uid to name, hex to text) | Linux |
| `bpftrace` | `bpftrace -l 'tracepoint:syscalls:*'` | List available probes | Linux |
| `bpftrace` | `bpftrace -lv 'tracepoint:syscalls:sys_enter_execve'` | Show probe arguments and types | Linux |
| `bpftrace` | `bpftrace -c '<command>' script.bt` | Run a script bounded by a child process's lifetime | Linux |
| `bpftrace` | `interval:s:30 { print(@); clear(@); }` | Periodic map snapshot and reset | Linux |

## Minimal Script

```powershell
# Run on the Linux host under audit (WSL or SSH); PowerShell wrapper shown for consistency.
wsl -u root auditctl -l | Select-String -Pattern 'process_exec'
if ($LASTEXITCODE -ne 0) { Write-Output "rules not loaded: run augenrules --load"; exit 2 }

wsl -u root ausearch -k process_exec -ts recent | Select-Object -First 5
wsl -u root bpftrace -l 'tracepoint:syscalls:sys_enter_execve'
if ($LASTEXITCODE -ne 0) { Write-Output "tracepoint unavailable on this kernel"; exit 2 }

python -m py_compile .\audit_parse.py
exit $LASTEXITCODE
```

Exit-code contract: `0` rule loaded, records produced for a triggered event, and probe attachable; `1` rule missing or no records for a known-triggered event; `2` audit tools unavailable or tracepoint absent.
