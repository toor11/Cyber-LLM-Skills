# Operational Triage and Response Playbook

> Sub-skill: [`super-timeline-and-plaso-postprocessing-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a timeline-reduction incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A reduced timeline reports no activity around a known incident.
- An investigator cannot find an artefact they previously saw in the full export.
- A Timesketch import fails or shows blank host/message fields.
- Row counts do not reconcile after a reduction.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Seed not found in its own window | Timezone mismatch | Re-derive the seed offset and re-run; never widen windows to "find" it |
| Artefact present in full export, absent in reduced | Over-broad noise rule | Exempt the source, re-run, and keep the per-rule counts |
| Blank host or message columns | Field rename | Resolve both old and new Plaso names |
| Import rejected | Missing mandatory column | Carry `message`, `datetime`, `timestamp_desc` through |
| Counts do not reconcile | Accounting defect | Stop and fix before the timeline is used in a report |

## Containment and Recovery

1. **Preserve before mutating:** keep the full export, the seed list, the rule set, and the manifest. A reduction is only defensible alongside its accounting.
2. **Check blast radius:** determine whether the defect affected one case or every timeline produced by the same script, and whether reports were issued from it.
3. **Eradicate the root cause:** fix the timezone handling or rule scope, re-reduce from the retained full export, and re-issue the timeline with its manifest attached.
