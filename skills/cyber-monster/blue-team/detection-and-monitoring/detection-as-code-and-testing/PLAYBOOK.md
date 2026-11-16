# Operational Triage and Response Playbook

> Sub-skill: [`detection-as-code-and-testing`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `detection-as-code-and-testing`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- A rule is about to be promoted and the pipeline has no compiled artefact to review.
- A deployed rule is suspected of drifting from the repository after an incident hotfix.
- A rule changed behaviour after a schema change (an ECS field removal, an OCSF object rename) and no fixture caught it.
- A correlation rule was authored and its window has never been exercised by a test.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Positive fixture hits, negative fixture does not, correlation window pair behaves, artefact and deployment record exist | Control Satisfied | Promote with the commit stamp; retain the artefact so the next drift check has a baseline |
| Negative fixture fires while the positive fixture also fires | Control Gap (Precision) | Block promotion; add the discriminating condition to the source, then re-run the replay before re-reviewing |
| Compiled output empty or conversion errored for a declared backend | Control Gap (Compilation) | Fix the unsupported logsource or modifier, or drop that backend from the rule's declaration with a written reason |
| Deployed rule text differs from the built artefact | Control Gap (Drift) | Reconcile by committing the console change through review, or redeploy the artefact; record which direction the fix went |
| Rule has a source but no fixture pair at all | Inconclusive (Untested) | Author the positive and negative fixtures before the rule is described as tested; a rule without a negative fixture has unknown precision |
| Fixture no longer parses after a schema upgrade | Control Gap (Fixture Rot) | Repair the fixture against the current schema; a skipped fixture reports green and tests nothing |
| Historical sample window shorter than the declared comparison | Inconclusive (Retention Limit) | State the retention boundary and limit the regression claim to the window that exists |

## Containment and Recovery

1. **Preserve before mutating:** retain the failing artefact, the replay output, and the fixture that produced it; a fixed pipeline with no record of the failure cannot prove the fix.
2. **Roll back by artefact, not by memory:** redeploy the previously built artefact when a promotion misbehaves, and keep the commit it came from so the rollback is reproducible.
3. **Prefer removing coverage honestly over shipping unverified rules:** an unverified rule that fires on everything trains analysts to ignore the queue, which is worse than a declared coverage gap.
4. **Fix the gate, not the instance:** every manual reconciliation adds a condition to the pipeline; a drift found by hand should end with an automated check that would have found it.
