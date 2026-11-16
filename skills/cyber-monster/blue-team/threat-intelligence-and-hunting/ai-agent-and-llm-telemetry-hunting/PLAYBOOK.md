# Operational Triage and Response Playbook

> Sub-skill: [`ai-agent-and-llm-telemetry-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Structured runbook for `ai-agent-and-llm-telemetry-hunting`. Paired offensive/mechanics reference: [`rag-and-vector-store-attacks`](../../../red-team/ai-and-llm/rag-and-vector-store-attacks/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `hunt llm abuse`.
- Alert, hunt outlier, or review request matching `ai agent telemetry hunting`.
- Alert, hunt outlier, or review request matching `mcp tool anomaly`.
- Alert, hunt outlier, or review request matching `rag exfiltration hunt`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `tool_call sequence anomaly` corroborated by >=2 independent logs | Confirmed Malicious / Gap | Preserve volatile evidence, scope blast radius, initiate guarded containment |
| Matches documented admin change ticket or scanner | Benign Baseline | Record ticket ID, tune exclusion filter with narrow host/principal scope |
| Required log channel disabled or rotated out | Inconclusive (Telemetry Gap) | Do NOT close as clean; open high-priority log-onboarding action |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot volatile memory, active tokens/sessions, and raw logs with SHA-256 hashes.
2. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval.
3. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access.
