# Operational Triage and Response Playbook

> Sub-skill: [`osquery-extension-and-pack-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a fleet-visibility incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A pack that used to produce rows stops producing them.
- Log volume jumps after a pack change.
- A custom table reports nothing on a subset of hosts.
- A coverage report claims clean status for a control backed by osquery.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `file_events` empty fleet-wide | Publisher disabled or no `file_paths` category | Fix flags and path scope; re-verify with `osquery_flags` |
| One query stopped, others fine | Watchdog denylist | Reduce cost, split the query, alert on denylist entries |
| Volume spike after config change | Snapshot mode or interval change | Restore differential mode or raise the interval |
| Table absent on one OS | Platform-specific table | Add `platform` scoping or a per-OS query variant |
| Extension present but rows wrong | Schema/type mismatch | Coerce values in `generate()` to the declared column types |

## Containment and Recovery

1. **Preserve before mutating:** capture the effective `osquery_flags`, the deployed pack JSON, and the daemon log segment around the change; the flag state is not visible from the pack file alone.
2. **Check blast radius:** determine whether the change was fleet-wide or canary-scoped, and how long the gap lasted, since that defines the coverage hole to disclose.
3. **Eradicate the root cause:** correct the flag, mode, or schema, verify on one host per platform, then roll out and confirm rows return in the expected log destination.
