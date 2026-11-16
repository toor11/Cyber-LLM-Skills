# Operational Triage and Response Playbook

> Sub-skill: [`security-metrics-and-detection-coverage`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `security-metrics-and-detection-coverage`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `security metrics`.
- Alert, hunt outlier, or review request matching `mttd`.
- Alert, hunt outlier, or review request matching `mttr`.
- Alert, hunt outlier, or review request matching `detection coverage metric`.
- A period-over-period change that leadership or an auditor asks to explain.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Coverage drops sharply in one period with no rule deletions | Control Gap (measurement artefact) | Check tag continuity and the framework version first; if the rule corpus was re-imported, recompute both periods with the same mapping before reporting |
| MTTD p50 improves while the undetected-incident count rises | Control Gap | Split the two cohorts in the report; faster alerting with more missed incidents is a coverage regression, not a detection improvement |
| Precision rises and alert volume falls after a suppression batch | Control Gap (hidden coverage loss) | Publish the coverage delta alongside the precision delta, and list which techniques lost their only firing rule |
| A mapped technique's data source fails its null-rate or freshness contract | Inconclusive (Telemetry Gap) | Remove the technique from the collected tier, open the onboarding action, and re-run the coverage arithmetic rather than patching the number |
| Metric window crosses a retention boundary or a ticket schema migration | Inconclusive (Partial Period) | Shorten the window or label the period partial and name the boundary; do not extrapolate |
| Every tier agrees and the validated set grew with emulation evidence attached | Benign Baseline (healthy) | Publish movement with the evidence, and record the emulation artefacts that moved each row |

## Containment and Recovery

1. **Freeze the inputs before recomputing:** Snapshot the rule inventory, the mapping file and the ticket export together, with timestamps. Recomputation after a rule change produces a different number from the same data and destroys trust in both.
2. **Fix the definition, then the number:** When a metric misleads, the repair is a changed definition published with a restated prior period. Quietly republishing a corrected figure without restating history reads as manipulation.
3. **Attribute gaps to owners:** Every technique that fell out of the collected or validated tier gets an owner and a reason — source contract failure, rule retired, emulation not re-run. Unowned gaps recur.
4. **Never suppress to improve a metric:** Retiring a noisy rule is legitimate only with the coverage delta recorded; otherwise the next period shows improvement that was purchased with blindness.
5. **Verify by recomputation:** A published metric is verified when an independent run from the stored inputs reproduces it to the same rounding. If it cannot be reproduced, it should not be published.
