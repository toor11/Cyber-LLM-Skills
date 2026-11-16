---
name: auditd-and-ebpf-telemetry-collector-scripting
description: Authors Linux `auditd` rule generators/parsers (`ausearch`/`auparse`) and read-only `bpftrace`/libbpf observability scripts for `execve`, `connect`, `ptrace`, and sensitive file opens with kernel verifier-safe bounds and ring-buffer rate limits. Use when building Linux host security telemetry collectors.
family: security-automation-and-tool-development
tier: leaf
triggers: ["ebpf security script", "bpftrace execve", "auditd parser python", "linux telemetry script"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Auditd and eBPF Telemetry Collector Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **leaf** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Linux host telemetry has two independent pipelines with different guarantees. `auditd` is rule-driven and kernel-mediated: `auditctl` rules (`-a always,exit -F arch=b64 -S execve`) are evaluated in the kernel's syscall exit path, records are written to `/var/log/audit/audit.log`, and userspace tools (`ausearch`, `auparse`) reconstruct multi-record events — one `execve` typically produces a `SYSCALL` record plus one or more `EXECVE`/`CWD`/`PATH` records that must be reassembled by event serial number. Its weakness is volume: rules are either loaded at boot from `audit.rules` / `rules.d` fragments via `augenrules`, or set interactively and lost on restart, and an over-broad rule can saturate the log and then drop records. `bpftrace` is the complementary observational path: a small program attaches to a tracepoint or kprobe, aggregates in kernel-side maps, and prints on exit or on an `interval` probe. Its constraints are the verifier (bounded loops, no unbounded pointer chasing without `--unsafe`) and event volume — a per-event `printf` on a hot path saturates the perf/ring buffer, which is why aggregation into `@map` values and periodic `print`/`clear` is the correct shape. Choosing between them: auditd for durable, attributable, boot-persistent syscall and file-access records; bpftrace for ad-hoc, aggregated, low-overhead observability where you need counts and latency rather than per-event attribution.

- **CWE-778 (Insufficient Logging):** audit rules lost on reboot, records dropped under load, or a probe that quietly detaches all produce the same outcome — an activity class with no telemetry.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you need durable syscall or file-access records **THEN** write `auditctl` rules into `/etc/audit/rules.d/*.rules` and load them with `augenrules --load`, so they survive reboot; an interactive `auditctl -a` is lost on restart.
2. **IF** you are analyzing audit output **THEN** reassemble by `msg`/serial (`ausearch -a <serial>` or `auparse`), because a single event spans `SYSCALL`, `EXECVE`, and `CWD` records that only make sense together.
3. **IF** you need counts, latency, or rates rather than per-event attribution **THEN** use `bpftrace` with `@map` aggregation and an `interval` probe to `print` and `clear`, and never a `printf` on a high-frequency path.
4. **IF** a probe needs pointer dereference beyond verifier-safe bounds **THEN** redesign it; using `--unsafe` in production hands the script kernel-level capability and is out of scope for defensive tooling.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `auditd-and-ebpf-telemetry-collector-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable rule and probe shapes | [`QUERIES.md`](QUERIES.md) | `auditctl`/`augenrules` rules, `ausearch` parsing, `bpftrace` one-liners |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `auditctl`, `ausearch`, `auparse`, `bpftrace` invocation |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Rules lost on reboot and buffer saturation incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Host-telemetry handoff during live response |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Linux `auditd` (`auditctl`, `augenrules`, `ausearch`/`auparse`) for durable syscall records, plus `bpftrace` for aggregated read-only observability
- **Mandatory Self-Validation Command:** `python -m py_compile audit_parse.py; bpftrace --dry-run probe.bt 2>&1 | Select-String -Pattern 'error' -NotMatch`

1. **Confirm the inputs.** Establish the kernel version (probe availability and BTF support), whether `auditd` is running and configured with `-f 2` (immutable rules), the current rule set (`auditctl -l`), and where records are shipped. Confirm the probe's tracepoint exists with `bpftrace -l`.
2. **Choose the branch.** Durable attribution → auditd rules in `rules.d` plus `augenrules`. Rates and counts → `bpftrace` with map aggregation. Syscall argument detail → auditd, because `EXECVE` records carry argv that a bpftrace one-liner would have to reconstruct.
3. **Define how to validate the collector.** For auditd: confirm `auditctl -l` lists the rule, trigger a benign instance of the activity (run the audited syscall on a test path), and confirm the expected record type appears in `audit.log` within the same serial group. For bpftrace: run the script with `-c` against a controlled command, confirm the map prints the expected key, and confirm the script exits on its own.
4. **Name the stop condition.** Stop when `auditctl -l` does not show the rule after a load, when audit records for a known-triggered event do not appear, when `auditd` reports lost records in its own log, when a probe fails to attach, or when a probe's map grows without an `interval` clear on a long run.
5. **State what counts as a working tool.** A working collector has boot-persistent rules that appear in `auditctl -l`, produces reassemblable record groups for a triggered event, reports its own loss counters, and exits non-zero when a rule or probe fails to load.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `auditctl -l` listing the rule after `augenrules --load` | Proves the rule is loaded and persistent, not just present on disk |
| `ausearch -a <serial>` returning `SYSCALL` + `EXECVE` + `CWD` | Proves the event was reassembled, which is the only form with usable argv and path |
| `auditd` lost-record counters in `/var/log/audit/audit.log` or `auditd` stats | Proves whether telemetry was dropped under volume |
| `bpftrace -l 'tracepoint:syscalls:sys_enter_execve'` | Proves the probe exists on this kernel before the script depends on it |
| `interval:s:30 { print(@); clear(@); }` in a bpftrace script | Proves map growth is bounded on a long-running probe |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: treats each audit line as a complete event, so argv and cwd never
# appear; also ignores the possibility that rules were never loaded.
import subprocess

def execve_commands():
    out = subprocess.run(["grep", "type=EXECVE", "/var/log/audit/audit.log"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        print("command:", line.split("a0=")[-1])       # fragments, no reassembly
```

**Production-Grade Starter Skeleton (USE):**

```python
# audit_parse.py - Reassemble audit events by serial and emit one JSON object per event.
# Exit 0 parsed, 1 no events found, 2 log unreadable.
import json
import pathlib
import re
import sys

EVENT_RE = re.compile(r"^type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)$")
KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")

def parse_log(path: pathlib.Path) -> list[dict]:
    groups: dict[str, dict] = {}
    for line in path.read_text(errors="replace").splitlines():
        m = EVENT_RE.match(line)
        if not m:
            continue
        record_type, _ts, serial, rest = m.groups()
        event = groups.setdefault(serial, {"serial": serial, "records": {}, "argv": []})
        event["records"].setdefault(record_type, []).append(rest)
        if record_type == "EXECVE":
            for key, value in KV_RE.findall(rest):
                if key.startswith("a") and key[1:].isdigit():
                    event["argv"].append((int(key[1:]), value.strip('"')))
        if record_type == "SYSCALL":
            for key, value in KV_RE.findall(rest):
                event[key] = value.strip('"')
    out = []
    for event in groups.values():
        syscall = event.get("syscall", "")
        argv = [v for _, v in sorted(event["argv"])]
        out.append({
            "serial": event["serial"],
            "syscall": syscall,
            "exe": event.get("exe", ""),
            "comm": event.get("comm", ""),
            "pid": event.get("pid", ""),
            "uid": event.get("uid", ""),
            "argv": argv,
        })
    return out

def main() -> int:
    path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/var/log/audit/audit.log")
    if not path.is_file():
        sys.stderr.write(f"fatal: unreadable audit log {path}\n")
        return 2
    events = [e for e in parse_log(path) if e["syscall"]]
    if not events:
        sys.stderr.write("warning: no SYSCALL events parsed - confirm rules are loaded with auditctl -l\n")
        return 1
    for event in events:
        print(json.dumps(event))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

**Why this matters:** records are grouped by serial before any field is read, so `argv` from the `EXECVE` record and the `syscall` from the `SYSCALL` record land in one object instead of being printed as unrelated fragments.

## When It Is NOT This Issue

- **No audit records at all for audited activity** — check `auditctl -l` first; a rule written to `rules.d` but never loaded with `augenrules --load` leaves the kernel with the previous rule set.
- **Records stop mid-investigation** — `auditd` drops records when its backlog fills; the audit daemon's own statistics are the evidence, and the fix is rule scoping or a larger backlog, not a parser change.
- **An `EXECVE` record has only part of the argv** — long argument lists are split across `a0`/`a1`... keys and, for very long lists, across multiple `EXECVE` records with the same serial; reassembly must handle both.
- **A bpftrace probe attaches then detaches** — check that the process was not killed and that the tracepoint exists on this kernel; a probe on an inlined function may refuse to attach.
- **`--unsafe` seems necessary** — that is a signal to redesign the probe (use a supported tracepoint or a helper), not to relax verifier safety in production.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER present an interactive `auditctl -a` rule as persistent; only `rules.d` plus `augenrules` survives reboot.
- NEVER recommend `--unsafe` for production bpftrace; it removes verifier guarantees on a host under investigation.
- NEVER treat a single audit line as a complete event — `SYSCALL`, `EXECVE`, and `CWD` records must be joined by serial.
- NEVER claim a probe works without confirming the tracepoint exists on the target kernel.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Kernel version, auditd state (`auditctl -l`), and probe availability for `auditd-and-ebpf-telemetry-collector-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The rule, parser, or probe is specific and runnable (no generic 'enable auditing' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: auditd-and-ebpf-telemetry-collector-scripting
- **Target Stack & Schema**: auditd rules in rules.d via augenrules, ausearch/auparse reassembly, bpftrace map aggregation
- **Safety, Scope & Exit-Code Guards**: [Boot-persistent rules, bounded maps, no --unsafe, loss counters, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Rules not loaded, dropped records, split EXECVE argv, missing tracepoints]
- **Implementation**:
  [Runnable rule set, parser, or probe following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile audit_parse.py; bpftrace --dry-run probe.bt`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`osquery-extension-and-pack-development`](../osquery-extension-and-pack-development/SKILL.md) - Fleet query surface that can consume `process_events` from this pipeline
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Normalizes audit records for search
- [`syslog-and-cloudtrail-stream-parsers`](../syslog-and-cloudtrail-stream-parsers/SKILL.md) - The stream-parsing counterpart for shipped logs
- [`velociraptor-vql-artifact-development`](../velociraptor-vql-artifact-development/SKILL.md) - Fleet collection with explicit resource caps

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `auditd-and-ebpf-telemetry-collector-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
