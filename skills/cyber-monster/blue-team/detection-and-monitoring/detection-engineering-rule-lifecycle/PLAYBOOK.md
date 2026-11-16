# Operational Triage and Response Playbook

> Sub-skill: [`detection-engineering-rule-lifecycle`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `detection-engineering-rule-lifecycle`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- A portfolio review is due and the catalogue has grown without any rule being retired.
- A rule is suspected of not firing since an agent or schema upgrade.
- An owning team dissolves or a rule owner leaves the organisation.
- A framework release restructures the techniques the catalogue references.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Fixture replay passes, sampled precision acceptable, owner set, review date set | Keep | Record the row and schedule the next review; change nothing |
| Fixture replay passes, sampled precision poor, dispositions name a narrow benign rationale | Tune | Route to tuning with the rationale set, and re-fire the positive after the change |
| Fixture replay fails while the artifact still exists on the current sensor build | Control Gap (Broken Rule) | Fix selection or field mapping, or retire with a replacement; a broken rule is not coverage |
| Fixture replay fails and the artifact no longer exists on any build | Control Gap (Unmaintainable) | Retire with a documented coverage gap or a visibility request naming the missing sensor |
| No dispositions in the window and replay passes | Benign Baseline (Rare Behaviour) | Keep, but extend the review interval and record why rare is expected |
| Two rules share the same analytic and platform, one with materially better precision | Duplicate Coverage | Retire the weaker rule with a pointer to the survivor; do not consolidate by age |
| Mapped technique was merged into a new parent in the framework release | Control Gap (Mapping) | Re-map the reference; do not retire, since the rule may still be correct |
| Logsource silent while other sources are healthy | Inconclusive (Pipeline) | Escalate as an ingestion outage; no lifecycle decision is valid until telemetry returns |

## Containment and Recovery

1. **Preserve before mutating:** keep the deployed text hash, the replay output, and the catalogue metadata for each transition so a later reviewer can reconstruct the decision.
2. **Never retire without a replacement or a written gap:** retiring a rule reduces coverage; the gap must appear in the coverage report the same week, not in a closing comment.
3. **Assign ownership at transition time:** a rule moved to a new team without an owner is orphaned on arrival, and orphaned rules are the ones that decay silently.
4. **Re-validate after every agent or framework upgrade:** add the fixture replay to the upgrade checklist so a field rename or a merged technique is discovered by a test rather than by a missed detection.
