# Operational Triage and Response Playbook

> Sub-skill: [`diamond-model-and-campaign-clustering`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Structured runbook for `diamond-model-and-campaign-clustering`. Paired offensive/mechanics reference: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `diamond model cti`.
- Alert, hunt outlier, or review request matching `analysis of competing hypotheses`.
- Alert, hunt outlier, or review request matching `intrusion set clustering`.
- Alert, hunt outlier, or review request matching `estimative language cti`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `Diamond Model vertex` corroborated by >=2 independent logs | Confirmed Malicious / Gap | Preserve volatile evidence, scope blast radius, initiate guarded containment |
| Matches documented admin change ticket or scanner | Benign Baseline | Record ticket ID, tune exclusion filter with narrow host/principal scope |
| Required log channel disabled or rotated out | Inconclusive (Telemetry Gap) | Do NOT close as clean; open high-priority log-onboarding action |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot volatile memory, active tokens/sessions, and raw logs with SHA-256 hashes.
2. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval.
3. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access.
