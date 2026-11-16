# Operational Triage and Response Playbook

> Sub-skill: [`mitre-attack-mapping`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `mitre-attack-mapping`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `mitre attack`.
- Alert, hunt outlier, or review request matching `attack mapping`.
- Alert, hunt outlier, or review request matching `attack coverage`.
- Alert, hunt outlier, or review request matching `technique mapping`.
- A board or audit request for a coverage number.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Alert carries technique tags whose definitions do not match the observed process lineage | Control Gap (mapping defect) | Re-derive the mapping from the event fields, strip unjustified tags, and record what the alert does not evidence |
| Mapped technique's Data Component shows no ingestion for the alert window | Inconclusive (Telemetry Gap) | Do NOT count the row as covered; open the onboarding action and mark the technique nominal-coverage until the source passes |
| Emulation of a mapped technique produces no alert | Control Gap (detection defect) | Capture the emulation telemetry, confirm the rule fired or did not, and hand the artefact to detection engineering with the mapping attached |
| Layer references `T1562` or another ID absent from the pinned release | Control Gap (stale layer) | Regenerate against the current bundle and re-map the behaviours to `T1685` and its sub-techniques before publishing |
| Coverage percentage stated without a denominator | Benign Baseline (reporting defect) | Reissue with the relevant-technique count, the ATT&CK version and the proof tier named |
| Behaviour is a benign owner's normal job, such as a patch agent creating a scheduled task | Benign Baseline | Record the owning tool against the technique so the row reads as accounted-for rather than as a gap or an alert |

## Containment and Recovery

1. **Freeze the version before anything else:** Record the ATT&CK release, Navigator layer schema version and the rule corpus commit in the layer description. Without these the artefact is not reproducible.
2. **Quarantine unjustified tags rather than deleting them:** Move a disputed technique tag to a `not_claimed` note with the reason, so the next reviewer sees why the mapping changed instead of finding a silent edit.
3. **Re-validate before re-reporting:** Any row that moves from `deployed` to `validated` needs an emulation or replay artefact attached; a re-run of the same rule against the same sample does not constitute new validation.
4. **Close gaps with owners and dates:** Every technique in the gap list gets a named owner and a target date, or it is explicitly accepted as out of scope with a rationale. An unowned gap list is a wish list.
5. **Publish movement, not the point value:** Report coverage change with both numerators and the delta since the last period; a static percentage across quarters is more often a stale layer than a stable programme.
