# Operational Triage and Response Playbook

> Sub-skill: [`windows-forensic-artifact-parser-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for an artifact-parsing incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A parser reports zero rows for an artefact class known to be populated.
- A timestamp contradicts other evidence (logs, memory, network).
- Evidence hashes change during analysis.
- A timeline shows implausible clustering of events.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Hive values older than logs indicate | Transaction logs not applied | Copy logs, reparse on a fresh copy, record `logs_applied` |
| Prefetch counters implausible | Wrong layout for that version | Branch on metrics offset; reparse and record layout |
| Single timestamp per file | MACB collapsed | Emit per-attribute rows and rebuild the timeline |
| Hash drift during parse | Evidence mutation | Stop, re-acquire from the image, and re-run against a copy |
| Zero rows, other classes fine | Version unsupported | Report unsupported explicitly; do not imply absence |

## Containment and Recovery

1. **Preserve before mutating:** keep the input manifest, the parser and library versions, and the raw output rows. A derived timeline without these cannot be defended.
2. **Check blast radius:** determine whether the defect affects one artefact or every case processed by the same script, and how many reports were issued from it.
3. **Eradicate the root cause:** fix the layout branch, apply logs, or split timestamps, then re-parse from the original copy and re-issue affected reports with the corrected provenance.
