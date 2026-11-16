# Operational Triage and Response Playbook

> Sub-skill: [`secrets-management-and-key-custody`](SKILL.md) | Family: **Application Security**

Structured runbook for `secrets-management-and-key-custody`. Paired offensive/mechanics reference: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `secrets management`.
- Alert, hunt outlier, or review request matching `key custody`.
- Alert, hunt outlier, or review request matching `vault`.
- Alert, hunt outlier, or review request matching `kms`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `vault` corroborated by >=2 independent logs | Confirmed Malicious / Gap | Preserve volatile evidence, scope blast radius, initiate guarded containment |
| Matches documented admin change ticket or scanner | Benign Baseline | Record ticket ID, tune exclusion filter with narrow host/principal scope |
| Required log channel disabled or rotated out | Inconclusive (Telemetry Gap) | Do NOT close as clean; open high-priority log-onboarding action |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot volatile memory, active tokens/sessions, and raw logs with SHA-256 hashes.
2. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval.
3. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access.
