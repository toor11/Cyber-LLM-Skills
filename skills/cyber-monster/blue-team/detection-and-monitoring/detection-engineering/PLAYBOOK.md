# Operational Triage and Response Playbook

> Sub-skill: [`detection-engineering`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `detection-engineering`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- A technique is exercised in an exercise or a real intrusion and no alert appeared for it.
- A rule's false-positive share is high enough that analysts close it without investigating.
- A framework or schema release renames or removes the artifact an analytic reads.
- Coverage is claimed for a technique and nobody can name the analytic, platform, or sensor behind the claim.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Artifact present on the platform, positive fires, negative does not, sampled precision acceptable | Detection Confirmed | Record strategy, analytic, platform, and depth; schedule the review date |
| Artifact absent on every platform in scope | Control Gap (Visibility) | Convert to a visibility request naming the sensor, event identifier, and field set with an owner and a date |
| Artifact present but the decisive field is unmapped or renamed | Control Gap (Schema) | Fix extraction or the pipeline, then re-derive the rule against the current mapping before re-testing |
| Positive fires and the negative also fires | Control Gap (Discrimination) | Add the discriminating entity or rate; do not promote and do not tune by threshold alone |
| Rule maps only by executable name and matches the whole management estate | Control Gap (Specificity) | Rewrite around a parent-child pair, an access right, or a first-seen destination; retire the broad version |
| Deployed rule exists but its original artifact is gone after an upgrade | Inconclusive (Provenance Broken) | Re-derive from the current sensor inventory; state which version the old rule was written against |
| Technique mapped but no analytic covers a platform in the estate | Control Gap (Depth) | Downgrade the depth rating to `none` for that platform and open the analytic as work rather than counting the existing rule |

## Containment and Recovery

1. **Preserve before mutating:** keep the old rule text, the compiled artefact, and the fixture results so a regression can be attributed rather than guessed.
2. **Retire rather than silence:** a noisy rule removed without a replacement leaves a technique uncovered; remove it in the same change that ships the narrower analytic, or record the gap explicitly.
3. **Check blast radius of a mapping change:** one analytic may satisfy several techniques; changing it can move coverage across a whole tactic, so update the mapping table in the same commit.
4. **Feed the result back into visibility work:** every coverage gap whose root cause is a missing sensor becomes a named data-source request, not a note in a rule comment.
