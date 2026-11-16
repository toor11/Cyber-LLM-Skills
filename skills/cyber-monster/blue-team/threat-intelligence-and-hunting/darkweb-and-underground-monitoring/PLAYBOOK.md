# Operational Triage and Response Playbook

> Sub-skill: [`darkweb-and-underground-monitoring`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Structured runbook for `darkweb-and-underground-monitoring`. Paired offensive/mechanics reference: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `darkweb monitoring`.
- Alert, hunt outlier, or review request matching `underground monitoring`.
- Alert, hunt outlier, or review request matching `leaked credentials monitoring`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `credential leak` corroborated by >=2 independent logs | Confirmed Malicious / Gap | Preserve volatile evidence, scope blast radius, initiate guarded containment |
| Matches documented admin change ticket or scanner | Benign Baseline | Record ticket ID, tune exclusion filter with narrow host/principal scope |
| Required log channel disabled or rotated out | Inconclusive (Telemetry Gap) | Do NOT close as clean; open high-priority log-onboarding action |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot volatile memory, active tokens/sessions, and raw logs with SHA-256 hashes.
2. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval.
3. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access.
