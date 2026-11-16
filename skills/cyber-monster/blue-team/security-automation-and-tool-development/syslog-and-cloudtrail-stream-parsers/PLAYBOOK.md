# Operational Triage and Response Playbook

> Sub-skill: [`syslog-and-cloudtrail-stream-parsers`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a cloud-audit ingestion incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A cloud account shows no events for a period where activity is known.
- Record counts per batch fall sharply without a change in account activity.
- A logging-control API call appears in the feed.
- Parsed output shows implausible timestamps or shifted fields.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Zero records from a present object | Read/envelope defect or disabled trail | Check trail status and selectors; treat as an error, not a quiet period |
| Count matches only the first event | `Records[0]` defect | Iterate the array and reconcile per file |
| `StopLogging`/`UpdateTrail` present | Visibility change | Escalate immediately; confirm current trail configuration |
| CEF fields shifted | Tokenization defect | Fix escape-aware split and re-parse from the raw line |
| Timestamps offset by a constant | Timezone assumption | Require an explicit offset; apply the feed's documented zone |

## Containment and Recovery

1. **Preserve before mutating:** retain the raw batch files, the parse revision, and the per-file record counts; the raw objects are the only complete record of what was delivered.
2. **Check blast radius:** identify every account, subscription, or project feeding the same pipeline before changing the parser; a shared projection defect affects all of them.
3. **Eradicate the root cause:** restore or re-enable logging, fix the parse defect, replay the retained raw batches, and confirm reconciliation before closing the gap.
