# Operational Triage and Response Playbook

> Sub-skill: [`siem-query-and-log-analysis`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `siem-query-and-log-analysis`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `siem query`.
- Alert, hunt outlier, or review request matching `splunk query`.
- Alert, hunt outlier, or review request matching `kql`.
- Alert, hunt outlier, or review request matching `elastic query`.
- A hunt hypothesis that needs a cross-source query rather than a single rule.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Per-key differential shows one principal's probe count above baseline mean plus three standard deviations, corroborated by a second source in the same UTC minute | Confirmed Malicious | Freeze both query results with their job IDs, extract the principal and host, and pivot to endpoint or identity telemetry before any containment |
| Query returns zero rows for a source the inventory says is active | Inconclusive (Scope Error) | Re-run with the enumerated index or table from the inventory before interpreting the zero; do not report clean |
| Job reports a row ceiling, subsearch timeout or failed shards | Inconclusive (Truncated Result) | Narrow the window or raise the ceiling, re-run, and disclose the ceiling in any published number |
| Decisive field shows a large unmapped share for the event type under review | Inconclusive (Field Gap) | Hand to [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) with the null-rate evidence; the aggregation cannot be trusted until it is fixed |
| Two sources disagree on whether the activity occurred | Benign Baseline (for the minority source) | Determine which source is closer to the behaviour, state the disagreement, and treat the weaker source's silence as unproven rather than as exculpatory |
| Activity is explained by a documented change window from a known management host | Benign Baseline | Record the ticket and keep the principal in the baseline rather than excluding the index |

## Containment and Recovery

1. **Freeze the query, not just the result:** Save the exact query text, the time range, the job or search ID and the ceiling that applied. A result without its query is not reproducible and will not survive review.
2. **Contain on the strongest source:** If endpoint and identity evidence agree on a principal and host, contain that pair. Do not contain on a single-source aggregate, because a parser change can produce the same shape.
3. **Preserve the window before it ages out:** Hot-tier retention is the binding constraint during an investigation. Export the slices you will need for the full window early, with hashes.
4. **Re-run after any pipeline or parser change:** A query result is only valid for the schema state it ran against. After a parser fix, re-run the same query and report the new result as a new observation.
5. **Verify containment by the same differential:** Re-run the baseline-versus-probe comparison over the post-containment window and confirm the specific key returned to baseline, rather than confirming that all alerts stopped.
