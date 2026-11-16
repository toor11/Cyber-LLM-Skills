# Operational Triage and Response Playbook

> Sub-skill: [`zeek-script-and-notice-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a sensor-script incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- Worker memory or CPU rises after deploying a new `.zeek` policy script.
- A declared notice type produces no page despite entries in `notice.log`.
- Post-upgrade notices name the wrong host for HTTP attack traffic.
- A `btest` case fails after a Zeek minor-version bump.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Global table with no `&create_expire`, memory climbing | Script defect | Move the counter into a `SumStats` reducer with an epoch, or add an expiry |
| `notice.log` rows present, no escalation | Routing gap | Add the type to `Notice::policy` with an explicit action |
| Cluster counts lower than standalone replay | Aggregation defect | Replace worker-local state with `SumStats` |
| Post-upgrade host attribution flipped | Version semantics change | Confirm which detection script produced the notice via `uid`/`dst` presence, then re-map consumers |
| Script fails to load only in CI | Load path | Pass the script by explicit path or add it to `ZEEKPATH`; never assume interactive paths |

## Containment and Recovery

1. **Preserve before mutating:** keep the script revision, `zeek --version`, the fixture PCAP, and the generated `notice.log` together. A script defect without the replay fixture cannot be proven fixed.
2. **Check blast radius:** determine whether the script runs on a standalone sensor or across cluster workers before changing thresholds; the same threshold means different things in each topology.
3. **Eradicate the root cause:** fix state bounds or routing, re-run the positive/benign differential, and only then restore the previous alerting scope.
