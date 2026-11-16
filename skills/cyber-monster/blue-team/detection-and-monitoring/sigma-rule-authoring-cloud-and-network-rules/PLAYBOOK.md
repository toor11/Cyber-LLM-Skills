# Operational Triage and Response Playbook

> Sub-skill: [`sigma-rule-authoring-cloud-and-network-rules`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `sigma-rule-authoring-cloud-and-network-rules`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `sigma cloud`.
- Alert, hunt outlier, or review request matching `sigma network`.
- Alert, hunt outlier, or review request matching `sigma proxy`.
- A cloud or proxy rule that deployed successfully and has never fired.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Converted rule fires on a captured event of the exact service and log type, subscription confirmed, and the quiet-window count for the same principal is near zero | Benign Baseline (rule healthy) | Deploy with the trail selector output and converted query recorded beside the rule |
| Rule targets object-level operations and the trail has no data-event selectors | Inconclusive (Telemetry Gap) | Do NOT report clean; raise the selector change as a separate control action and record that no historical data can exist |
| Converted query names no provider source, only a generic placeholder | Control Gap (pipeline mapping) | Re-target to a mapped product-and-service pair or add the pipeline mapping; the rule cannot match as written |
| CloudTrail operation listed in the rule is absent from 30 days of real traffic while a near-identical name appears | Control Gap (operation drift) | Confirm the current operation name against captured events, update the rule, and note which version introduced it |
| Proxy rule keys on an `sc-status` or action value the proxy never emits | Control Gap (field mismatch) | Read the action and status distribution from the proxy and rewrite the selection against values that exist |
| DNS rule shows no matches while endpoint-side DNS evidence shows the queries | Inconclusive (Resolver Visibility) | Determine whether the resolver logs cache misses only or is sampled; the feed, not the rule, is the problem |

## Containment and Recovery

1. **Preserve the captured event and the trail configuration:** Store one raw event of the target type plus the `get-event-selectors` output with the rule. Without them a later silence cannot be attributed to a subscription change.
2. **Fix the rule at the source, never in the converted query:** The converted text is regenerated on every pipeline run; a manual edit becomes a second, conflicting definition.
3. **Separate the control action from the detection action:** Enabling a data-event selector is a change with cost and volume implications. Track it as its own item so the detection gap closes with an owner and a date.
4. **Re-validate after any provider API or pipeline upgrade:** Operation names, field paths and pipeline mappings all drift. Re-run the subscription and conversion gates before assuming the rule still has input.
5. **Verify with two sources where possible:** For network destinations, confirm the proxy and the DNS feed agree on the same domain, rather than trusting a single logsource's silence.
