# Operational Triage and Response Playbook

> Sub-skill: [`sigma-rule-authoring`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `sigma-rule-authoring`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `sigma rule`.
- Alert, hunt outlier, or review request matching `sigma authoring`.
- Alert, hunt outlier, or review request matching `write sigma`.
- Alert, hunt outlier, or review request matching `sigma conversion`.
- A converted rule deployed to a backend that never produced an alert.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Converted rule fires on the positive replay and stays quiet on the 7-day baseline | Benign Baseline (rule healthy) | Deploy with the conversion command, backend, pipeline and pySigma version recorded beside the rule |
| Rule validates and converts, but the converted query names no real source or a placeholder | Control Gap (pipeline mapping) | Re-target the rule to a category the pipeline maps, or add the mapping; the rule as written can never match |
| Detection block contains vendor field names rather than Sigma field names | Control Gap (portability) | Replace with Sigma names and move the rename into the processing pipeline so the rule survives a backend change |
| Rule needs a count, threshold or ordering and is written as a single selection | Control Gap (wrong construct) | Split into a base rule plus a correlation document, keeping the meta fields on the outermost correlation rule |
| Converted rule produces thousands of hits per day on ordinary activity | Benign Baseline (needs tuning) | Add the documented exclusions as actual filter conditions, or narrow the selection; a prose-only `falsepositives` entry changes nothing |
| `--skip-unsupported` was used and the deployed set is smaller than the source set | Inconclusive (Silent Skip) | Count and list the skipped rules, re-run without the flag to see each reason, and record what is not covered |

## Containment and Recovery

1. **Preserve the conversion context:** Save the rule source, converted query, target, pipeline name and pySigma version together. A converted rule detached from its pipeline cannot be re-derived and will drift on the next upgrade.
2. **Never patch the converted query:** Editing the generated query creates a second source of truth that the next conversion overwrites. Fix the rule or the pipeline, then regenerate.
3. **Contain a noisy rule by narrowing the selection, not by suppressing the alert:** Suppression hides the rule's behaviour from the baseline and destroys the evidence needed to tune it.
4. **Re-validate after any pySigma or pipeline upgrade:** Modifier support and default policy handling change between releases; a rule that converted last quarter may convert into something different or be silently skipped.
5. **Verify with the same two-corpus test:** Re-run the positive replay and the 7-day baseline after every change, and record both counts. A rule is verified by firing where it should and staying quiet where it should not.
