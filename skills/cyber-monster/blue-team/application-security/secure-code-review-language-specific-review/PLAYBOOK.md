# Operational Triage and Response Playbook

> Sub-skill: [`secure-code-review-language-specific-review`](SKILL.md) | Family: **Application Security**

Structured runbook for `secure-code-review-language-specific-review`. Paired offensive/mechanics reference: [`codeql-query-development`](../../../red-team/security-assessment-tooling-and-automation/codeql-query-development/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `language security review`.
- Alert, hunt outlier, or review request matching `framework pitfall`.
- Alert, hunt outlier, or review request matching `orm injection review`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `deserialization` corroborated by >=2 independent logs | Confirmed Malicious / Gap | Preserve volatile evidence, scope blast radius, initiate guarded containment |
| Matches documented admin change ticket or scanner | Benign Baseline | Record ticket ID, tune exclusion filter with narrow host/principal scope |
| Required log channel disabled or rotated out | Inconclusive (Telemetry Gap) | Do NOT close as clean; open high-priority log-onboarding action |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot volatile memory, active tokens/sessions, and raw logs with SHA-256 hashes.
2. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval.
3. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access.
