# Operational Triage and Response Playbook

> Sub-skill: [`auditd-and-ebpf-telemetry-collector-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a Linux host-telemetry incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- An activity class that should be audited has no records.
- `auditd` reports dropped records or a full backlog.
- A probe fails to attach or detaches during an observation.
- A post-reboot review finds the rule set changed.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Rule on disk, absent from `auditctl -l` | Not loaded | `augenrules --load`, then re-verify |
| Loss counters rising | Volume defect | Narrow the rule with `auid`/`key`, increase backlog, re-test |
| Records present but argv missing | Reassembly gap | Parse by serial; handle split `a0..aN` |
| Probe will not attach | Kernel/probe mismatch | Confirm with `bpftrace -l` and redesign around a supported tracepoint |
| Host overhead during observation | Unbounded probe | Aggregate in maps, bound with `interval` and `-c` |

## Containment and Recovery

1. **Preserve before mutating:** capture `auditctl -l`, `auditctl -s`, the `rules.d` content, and the loss counters together; the active rule set is not inferable from the files alone.
2. **Check blast radius:** determine whether the rule set is host-specific or fleet-managed, and how long the telemetry gap lasted — that interval is the disclosure scope.
3. **Eradicate the root cause:** persist the rule, scope it, verify with a benign trigger, and confirm loss counters stay at zero under normal load before declaring coverage restored.
