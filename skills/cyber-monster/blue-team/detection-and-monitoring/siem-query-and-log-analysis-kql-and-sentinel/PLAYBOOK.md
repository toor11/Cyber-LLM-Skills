# Operational Triage and Response Playbook

> Sub-skill: [`siem-query-and-log-analysis-kql-and-sentinel`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `siem-query-and-log-analysis-kql-and-sentinel`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `kql`.
- Alert, hunt outlier, or review request matching `sentinel query`.
- Alert, hunt outlier, or review request matching `defender query`.
- Alert, hunt outlier, or review request matching `kusto`.
- An analytics rule that stopped producing alerts after a table was moved between tiers.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Per-entity aggregate above baseline, reconciled with row-level events, and a second table agrees on the account and device in the same UTC minute | Confirmed Malicious | Export the row-level results with `TimeGenerated` and device identifiers, then pivot to the endpoint process tree before containment |
| Analytics rule returns nothing while the table answers in Advanced Hunting | Inconclusive (Tier Mismatch) | The table is lake-only; move the detection to a Defender-side rule or scheduled job and record that no alert could have fired |
| Join with the default `innerunique` produced fewer rows than the left side has | Inconclusive (Join Collapse) | Re-run with an explicit `kind=` and compare counts; any number derived from the collapsed join is invalid |
| `summarize` ran before the filter that needed a detail column | Inconclusive (Granularity Loss) | Rewrite with the filter before the summarize and state where the granularity point is |
| Lake-tier query returned a row count at or near the documented limit | Inconclusive (Query Truncated) | Narrow the window or convert to a scheduled job, then re-run; do not report the partial set as the population |
| Aggregate outlier explained by a deployment tool's `make_set` of command lines on a small host group | Benign Baseline | Record the deployment tool as an owner of that parent process and keep it in the baseline |

## Containment and Recovery

1. **Preserve the row-level evidence, not the aggregate:** Export the individual events that produced the count, with `TimeGenerated`, `DeviceId` and account fields. An aggregate alone cannot be re-derived after the retention boundary passes.
2. **Confirm the tier before escalating a silence:** A rule on a lake-only table never fired and never errored. Establish that first, so the incident record says "no detection was possible" rather than "no activity occurred".
3. **Contain on the corroborated identity and device pair:** Act where the identity-plane and endpoint-plane evidence agree. A single-table aggregate identifies a candidate, not a target.
4. **Rebuild the rule after any tier or schema change:** Re-validate against a known-positive event and record the table's tier beside the rule so the next reviewer knows which side of the boundary it lives on.
5. **Verify with the same summarize shape:** Re-run the identical aggregation over the post-containment window and confirm the specific entity returned to baseline rather than that alert volume fell.
