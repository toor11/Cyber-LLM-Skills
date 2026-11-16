# Operational Triage and Response Playbook

> Sub-skill: [`threat-hunting-hunt-execution-and-triage`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Structured runbook for `threat-hunting-hunt-execution-and-triage`. Paired offensive/mechanics reference: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `hunt execution`.
- Alert, hunt outlier, or review request matching `hunt triage`.
- Alert, hunt outlier, or review request matching `hunt results`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Cluster with malicious ancestry and no baseline precedent | Escalate | Open an incident, preserve endpoint evidence, and hand the cluster to IR |
| Cluster matching a management or patch artefact | Baseline | Add the parent, path, or pattern to the hunt exclusion list with a review date |
| Cluster on hosts without sensor coverage | Coverage gap | Open a telemetry ticket and mark the hunt result as partial |

## Containment and Recovery

1. **Do not contain on a cluster alone.** Corroborate with a second source (network, identity, or endpoint) before isolating a host, because isolation on a false positive is itself an outage.
2. **Preserve the process tree and network connections** for any escalating cluster before the endpoint state changes.
3. **Record the exclusion** so the next hunt does not rediscover the same artefact; a hunt that repeats wastes the quarter.
