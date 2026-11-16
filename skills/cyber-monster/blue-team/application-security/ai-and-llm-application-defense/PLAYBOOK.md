# Operational Triage and Response Playbook

> Sub-skill: [`ai-and-llm-application-defense`](SKILL.md) | Family: **Application Security**

Structured runbook for `ai-and-llm-application-defense`. Paired offensive/mechanics reference: [`llm-prompt-injection`](../../../red-team/ai-and-llm/llm-prompt-injection/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `llm defense`.
- Alert, hunt outlier, or review request matching `ai application security defense`.
- Alert, hunt outlier, or review request matching `prompt injection mitigation`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `input isolation` corroborated by >=2 independent logs | Confirmed Malicious / Gap | Preserve volatile evidence, scope blast radius, initiate guarded containment |
| Matches documented admin change ticket or scanner | Benign Baseline | Record ticket ID, tune exclusion filter with narrow host/principal scope |
| Required log channel disabled or rotated out | Inconclusive (Telemetry Gap) | Do NOT close as clean; open high-priority log-onboarding action |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot volatile memory, active tokens/sessions, and raw logs with SHA-256 hashes.
2. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval.
3. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access.
