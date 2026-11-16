# Detection Queries and Telemetry Artifacts

> Sub-skill: [`auditd-and-ebpf-telemetry-collector-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Audit-rule, reassembly, and probe artifacts owned by this slug. Confirm rule and probe availability on the target kernel before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `auditctl -l` output containing the rule | High | The rule is loaded in the kernel, not merely written to disk |
| 2 | One serial producing `SYSCALL` + `EXECVE` + `CWD` records | High | The event is reassemblable; separate records carry argv and path |
| 3 | `auditd` lost/backlog counters above zero | High | Telemetry was dropped under volume; coverage has a hole |
| 4 | `bpftrace -l` listing the intended tracepoint | High | The probe can attach on this kernel |
| 5 | `interval` probe printing and clearing a map | High | Map growth is bounded on a long-running observation |

## Detection Artifacts

```text
[auditd-and-ebpf-telemetry-collector-scripting:rule-spec] rules live in /etc/audit/rules.d and are loaded by augenrules --load
[auditd-and-ebpf-telemetry-collector-scripting:filter-fp] a rule present in rules.d but absent from auditctl -l is not active
[auditd-and-ebpf-telemetry-collector-scripting:correlate] msg=audit(<ts>:<serial>) groups all records of one event
```

Persistent execve auditing and its verification (bash on the target host):

```bash
sudo tee /etc/audit/rules.d/40-execve.rules >/dev/null <<'EOF'
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k process_exec
EOF
sudo augenrules --load
sudo auditctl -l | grep -- 'process_exec'
sudo ausearch -k process_exec -ts recent | head -20
```

Reassembling a single event by serial, which is the only form with usable argv:

```bash
sudo ausearch -a 12345 -i
```

Aggregated execve counts with a bounded map, rather than per-event output:

```bash
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_execve {
  @execs[comm] = count();
}
interval:s:30 {
  print(@execs);
  clear(@execs);
}'
```

Confirm the probe exists and inspect its argument layout before relying on fields:

```bash
sudo bpftrace -l 'tracepoint:syscalls:sys_enter_*' | grep -c execve
sudo bpftrace -lv 'tracepoint:syscalls:sys_enter_execve'
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Record `auditctl -l` output and the audit daemon's loss counters beside any report derived from audit data.
- Scope rules with `auid`/`key` filters; an unfiltered syscall rule is the fastest way to saturate the audit backlog.
- Bound every observation probe with an `interval` clear; a long-running map without one grows until it is dropped.
