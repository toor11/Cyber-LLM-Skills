# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`auditd-and-ebpf-telemetry-collector-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative Linux telemetry failures, each with the artifact that proves the diagnosis.

## Case 1: Rules vanished after a reboot

- **Surface & Preconditions:** an administrator adds rules with `auditctl -a ...` during an investigation and documents them in the ticket.
- **Root cause & impact:** runtime rules are not persisted; after the next reboot the kernel has only what `/etc/audit/rules.d/` produced, so the audited activity silently stops being recorded and the gap is not visible in any log.
- **Verification & fix:** write rules into `rules.d` and load with `augenrules --load`; verify with `auditctl -l` after every load, and store that output with the rule file.

## Case 2: Audit records dropped under load

- **Surface & Preconditions:** a broad rule audits every `execve` on a busy build server with no `auid` filter.
- **Root cause & impact:** the audit backlog fills, the kernel drops records, and `auditd` reports loss. The log looks populated, so nobody suspects a gap until a specific event is missing.
- **Verification & fix:** scope rules with `auid>=1000`/`auid!=4294967295` and a `key`, monitor loss counters, and size the backlog. A rule that loses records is worse than a narrower rule that does not.

## Case 3: argv missing from the parsed event

- **Surface & Preconditions:** a parser prints one line per audit record and calls it an event.
- **Root cause & impact:** `SYSCALL`, `EXECVE`, and `CWD` are separate records joined by serial; reading them individually yields a syscall number without arguments or a command fragment without the executable path.
- **Verification & fix:** group by `msg=audit(<ts>:<serial>)` before extracting fields, and handle argv split across `a0..aN` keys and across multiple `EXECVE` records.

## Case 4: The probe saturated the trace buffer

- **Surface & Preconditions:** a `bpftrace` one-liner calls `printf` on every `sys_enter` for a hot syscall.
- **Root cause & impact:** at tens of thousands of events per second the perf/ring buffer saturates, events are dropped, and the host takes measurable overhead during the observation — which is exactly when telemetry accuracy matters.
- **Verification & fix:** aggregate into `@map` counters and `print`/`clear` on an `interval`; use `-c` to bound the script's lifetime to a controlled command.
