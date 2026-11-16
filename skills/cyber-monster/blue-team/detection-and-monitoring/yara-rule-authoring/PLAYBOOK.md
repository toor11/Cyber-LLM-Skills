# Operational Triage and Response Playbook

> Sub-skill: [`yara-rule-authoring`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `yara-rule-authoring`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `yara rule`.
- Alert, hunt outlier, or review request matching `yara authoring`.
- Alert, hunt outlier, or review request matching `write yara`.
- Alert, hunt outlier, or review request matching `yara signature`.
- A fleet scan that suddenly matches a large number of hosts.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Rule matches the positive set, stays at zero on the benign corpus, and a matched sample shows the expected string offsets | Confirmed Malicious | Quarantine the matched artefacts to a holding area with hashes recorded, then identify the executing process from endpoint telemetry |
| Rule matches a large fraction of the fleet including system binaries | Control Gap (precision) | Pull the matched string with `--print-strings`, identify the shared framework or runtime literal, and replace it with a structural condition before any containment |
| Rule was built from strings visible in a packed sample | Inconclusive (Packer Strings) | Unpack or dump the runtime image and rebuild from the unpacked code; the current strings belong to the packer |
| Memory scan returns nothing while the process was running | Inconclusive (Paged Out) | State that pages may be on disk and out of the image; acquire a full memory image or an extracted process dump before concluding |
| Rule compiles under legacy `yara` but is rejected by `yr` | Control Gap (engine mismatch) | Fix the construct for the deployed engine, or keep separate source sets while the fleet is mixed |
| Match appears only in one build of the family | Control Gap (robustness) | Add a structural condition that holds across builds and re-measure coverage against the family set |

## Containment and Recovery

1. **Preserve the artefact before quarantining:** Hash the matched file and record its path, size and timestamps, then move it to a holding area rather than deleting it. A deleted sample cannot be re-scanned against a corrected rule.
2. **Quarantine by rule, not by directory:** Move only the files the validated rule matched, into a per-case holding area, so the blast radius is reviewable and reversible.
3. **Fix precision before scaling the scan:** A rule that matches a large share of the fleet must be corrected first; deploying it wide produces an alert storm that buries the real matches.
4. **Re-scan the corrected rule over the same corpus:** Confirm the benign count returned to the agreed threshold and the positive coverage did not regress, both measured on the same engines and versions.
5. **Verify quarantine completeness:** Re-scan the affected hosts with the validated rule and confirm no further matches, rather than confirming that the previous matches are gone from their original paths.
