# Operational Triage and Response Playbook

> Sub-skill: [`atomic-red-team-validation`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `atomic-red-team-validation`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- A detection rule is about to be promoted and nobody can show it ever fired on the behaviour it names.
- A test cycle is scheduled in the purple-team calendar and the sensors, not just the rules, must be signed off.
- An analyst questions whether a quiet rule is quiet because nothing happened or because it cannot fire.
- A rule was rewritten for a new backend and its prior validation no longer applies to the compiled query.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Raw artifact harvested in-window and the expected rule identifier fired on the same host and principal | Validated | Record technique, test number, window, rule version, and cleanup result; close the validation item |
| Raw artifact present in the window, no alert for the expected rule | Control Gap (Rule or Mapping) | Diff the deployed compiled query against the artifact's fields; check modifier and pipeline handling, then field extraction for that sourcetype |
| Alert fired but no raw artifact exists for the same host and principal | Control Gap (Match Provenance) | Check for replay, backfill, or a neighbouring event that satisfies the condition; do not credit the rule |
| Prereq check reports prerequisites not met and the test no-oped | Inconclusive (Prerequisite Unmet) | Satisfy prereqs in the isolated range with `-GetPrereqs`, then re-run; never record the no-op as a negative |
| Sensor check-in stale, or channel baseline zero before execution | Inconclusive (Sensor Gap) | Fix agent or forwarder coverage first; the validation cannot distinguish rule defect from missing telemetry |
| Artifact appears hours after the run, outside the harvest window | Inconclusive (Ingestion Delay) | Re-query by event time with a widened window and record the measured delay for future runs |
| Test artifacts remain after cleanup | Control Gap (Contamination) | Remove the residue, then re-run the validation; residue will be attributed to an adversary by the next hunter |

## Containment and Recovery

1. **Preserve before mutating:** capture the harvested raw event, the alert record, the prereq output, and the cleanup verification with hashes; these four are the evidence a reviewer needs to reproduce the outcome.
2. **Bound the blast radius of the probe:** execute only on a dedicated range host that is clearly labelled in the asset inventory, never on a domain controller, a jump host, or any host with production credentials cached.
3. **Recover the host to a known state:** verify cleanup with a targeted enumeration, remove any payload left in a temporary directory, and reset the test account's credentials if the atomic touched authentication.
4. **Feed the result back into authoring:** a control gap becomes a rule change or a log-onboarding ticket with an owner and a date; a validation record that produces no follow-up action is a ritual.
