# Operational Triage and Response Playbook

> Sub-skill: [`ocsf-and-ecs-log-normalizer-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a normalization-pipeline incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A detection that depends on one feed stops firing while collection looks healthy.
- Dead-letter volume rises with no change in source volume.
- Events appear with implausible timestamps or cluster at a boundary hour.
- A schema or log-shipper upgrade precedes a coverage report drop.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Dead letters rising, input flat | Parser mismatch | Inspect the stored raw payload in the newest dead-letter entries; fix the mapping, replay the dead letters |
| Events shifted by a constant offset | Naive timestamp | Require an explicit offset; apply the source's documented timezone, never the collector's guess |
| `class_uid` set, `category_uid` default | Classifier defect | Derive category from class and assert the pair in fixtures |
| `event.category` empty in an ECS index | Wrong schema branch | Map the class onto the ECS triple instead of copying OCSF identifiers |
| Source sees sends, destination sees nothing | Collector, not normalizer | Compare counts at the collector boundary before editing mapping code |

## Containment and Recovery

1. **Preserve before mutating:** export the dead-letter file segment, the normalizer revision, and the schema version the destination enforces. The dead-lettered raw bytes are the only complete record of what was lost.
2. **Check blast radius:** determine how many feeds share the mapping module; a shared projection change affects every feed at once.
3. **Eradicate the root cause:** fix the mapping, replay the dead-letter segment through the corrected normalizer, and confirm zero residual entries before closing.
