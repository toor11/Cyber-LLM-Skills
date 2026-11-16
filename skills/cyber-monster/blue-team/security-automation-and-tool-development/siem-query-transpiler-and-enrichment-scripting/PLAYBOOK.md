# Operational Triage and Response Playbook

> Sub-skill: [`siem-query-transpiler-and-enrichment-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for an investigation-tooling incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A hunt returns nothing for an entity known to be active.
- Enrichment values are stale or missing across a batch of alerts.
- A query fails only in the automated path, not interactively.
- Results include unexpected hosts or fields.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Query returns a partial result | Truncation | Narrow the window or paginate; report partial explicitly |
| Unexpected entities in results | Value injection or wrong field | Allowlist and escape the interpolated value; verify with a hostile probe |
| Enrichment missing under load | Rate limiting or no cache | Add bounded TTL cache, pre-load local database |
| Empty result with a diagnostic message | Query error, not empty | Parse `results.Message`, fix the search, re-run |
| Interactive works, SDK fails | Client-side limits or auth scope | Check server timeout, row caps, and token scope |

## Containment and Recovery

1. **Preserve before mutating:** keep the query text with values elided, the time window, the SDK versions, and the raw response status; a verdict cannot be reconstructed from rows alone.
2. **Check blast radius:** determine whether the defect affects one hunt or every automated investigation using the same helper module.
3. **Eradicate the root cause:** fix the binding, window, or cache, re-run the original hunt, and confirm the result set matches an independent query before closing.
