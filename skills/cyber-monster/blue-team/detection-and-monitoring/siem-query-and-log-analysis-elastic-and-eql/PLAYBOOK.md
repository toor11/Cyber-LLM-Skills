# Operational Triage and Response Playbook

> Sub-skill: [`siem-query-and-log-analysis-elastic-and-eql`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `siem-query-and-log-analysis-elastic-and-eql`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `elastic query`.
- Alert, hunt outlier, or review request matching `eql`.
- Alert, hunt outlier, or review request matching `kibana query`.
- Alert, hunt outlier, or review request matching `elasticsearch dsl`.
- An Elastic detection rule that stops firing after a stack upgrade.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| EQL sequence match with `is_partial: false`, full events retrieved, and the success step from a source address outside the account's normal set | Confirmed Malicious | Export the matched documents with `_id` and index name, then pivot to endpoint process lineage for the same host and minute |
| EQL response with `is_partial: true` or `shard_failures` non-empty | Inconclusive (Partial Result) | Do NOT count the reduced match set as the full picture; re-run with `allow_partial_search_results=false` after the shard recovers |
| Aggregation shows a rare value but `sum_other_doc_count` is large | Inconclusive (Truncated Aggregation) | Re-query scoped to the suspected value with a `term` filter rather than raising `size` and timing out |
| Rule stopped firing after an upgrade and its query names `process.pgid`, `process.parent.pgid` or `service.node.role` | Control Gap (stale mapping) | Rewrite against current ECS fields and re-validate; those names were removed in ECS 9.0 and return empty without error |
| Detections fire only for hosts writing to the current backing index | Control Gap (rollover scope) | Widen the index pattern to the whole data stream and confirm `_data_stream` health |
| Rare parent-child pair explained by a documented application update on a few hosts | Benign Baseline | Record the application owner and add the pair to the prevalence baseline rather than excluding the parent process |

## Containment and Recovery

1. **Preserve documents with identity, not just content:** Export matched `_id`, `_index` and `_source` for every event in the finding. A document without its index and id cannot be re-fetched or proven unmodified.
2. **Fix the query before containing:** A finding built on a partial sequence is not a containment trigger. Re-run with partial results disabled and confirm the join still holds for the same entity.
3. **Contain on the corroborated entity:** Act on the host or identity that appears in both the sequence and the endpoint evidence. Sequence matches joined only on `user.name` frequently span several hosts.
4. **Re-validate after any mapping change:** A pipeline or index-template change can rename or drop a field the rule depends on. After the change, replay the rule against a known-positive document.
5. **Verify by re-running the identical body:** Confirm containment by re-running the same aggregation over the post-containment window and checking the specific key returned to baseline, not by observing that alert volume fell.
