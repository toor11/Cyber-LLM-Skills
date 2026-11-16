# Operational Triage and Response Playbook

> Sub-skill: [`java-spring-security-architecture`](SKILL.md) | Family: **Application Security**

Structured runbook for `java-spring-security-architecture`. Paired offensive/mechanics reference: [`insecure-deserialization`](../../../red-team/web-and-application/insecure-deserialization/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `spring security 6 review`.
- Alert, hunt outlier, or review request matching `securityfilterchain order`.
- Alert, hunt outlier, or review request matching `preauthorize spel`.
- Alert, hunt outlier, or review request matching `jackson jsontypeinfo`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `SecurityFilterChain` corroborated by >=2 independent logs | Confirmed Malicious / Gap | Preserve volatile evidence, scope blast radius, initiate guarded containment |
| Matches documented admin change ticket or scanner | Benign Baseline | Record ticket ID, tune exclusion filter with narrow host/principal scope |
| Required log channel disabled or rotated out | Inconclusive (Telemetry Gap) | Do NOT close as clean; open high-priority log-onboarding action |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot volatile memory, active tokens/sessions, and raw logs with SHA-256 hashes.
2. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval.
3. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access.
