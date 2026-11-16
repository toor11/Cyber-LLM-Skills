# Operational Triage and Response Playbook

> Sub-skill: [`log-source-onboarding-and-parsing`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `log-source-onboarding-and-parsing`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `log onboarding`.
- Alert, hunt outlier, or review request matching `log parsing`.
- Alert, hunt outlier, or review request matching `normalization`.
- Alert, hunt outlier, or review request matching `field mapping`.
- A detection that has never fired against a source believed to be onboarded.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Required field null-rate jumps from baseline to near-total while volume is flat | Control Gap | Diff the current parser branch against the last known-good mapping, reassign the new `event.dataset` to the correct parser, then replay a captured sample |
| Producer counter exceeds destination document count by more than the agreed margin | Control Gap | Inspect collector `send_failed` and output retry counters, bound the lost window, and mark every rule on that source `Inconclusive` for that window |
| Destination count exceeds producer counter | Benign Baseline (config defect) | Find the duplicate shipping path by `count` by `host` and `source`; remove the second path before trusting any volume-based rule |
| Pipeline dead-letter holds rejects for a security-relevant event type | Control Gap | Recover the rejected documents, fix the mapping, replay the window, then re-run the detections that depend on it |
| Producer setting for the required event type was never enabled | Inconclusive (Telemetry Gap) | Do NOT close as clean; raise a change request naming the exact setting, and record that no historical data can exist |
| Source is flowing with all required fields non-null and the rule still returns nothing | Control Gap (detection logic) | The gap is now in the rule, not the pipeline: hand off to [`detection-engineering`](../detection-engineering/SKILL.md) with the passing contract evidence attached |

## Containment and Recovery

1. **Preserve the current parser state:** Export the live pipeline definition, agent config and a raw sample from before the change. Without the pre-change sample, a regression cannot be proven to be a regression.
2. **Bound the exposure window:** Compute the first and last event with the broken field, and list every detection whose logic depends on it. Those alerts must be re-run against raw or archive data, not assumed absent.
3. **Fix forward, never silently:** Deploy the corrected mapping behind a test pipeline, replay the captured sample, and only then swap. A direct edit to a production parser destroys the evidence of what the previous mapping produced.
4. **Reconcile after the fix:** Re-run the three-number reconciliation for the affected hours and confirm the delta closes before declaring the source onboarded again.
5. **Record the gate results:** Store freshness, null-rate and reconciliation outcomes with the source's onboarding record so a future empty result is attributable to a named gate rather than to an absence of activity.
