# Operational Triage and Response Playbook

> Sub-skill: [`sigma-rule-authoring-windows-event-rules`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `sigma-rule-authoring-windows-event-rules`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `sigma windows`.
- Alert, hunt outlier, or review request matching `sysmon sigma`.
- Alert, hunt outlier, or review request matching `event id sigma`.
- A Windows rule that validates and deploys but has never fired on a fleet believed covered.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Converted rule fires on a captured event of the same ID and channel, audit state confirmed, and quiet-window hits concentrate on known management parents | Benign Baseline (rule healthy) | Deploy with the audit state and Sysmon config version recorded beside the rule |
| Rule selects on a Sysmon ID absent from the running config | Inconclusive (Config Gap) | Do NOT close as clean; raise a config change for that event type, noting that no historical events exist for it |
| Rule selects 27 or 28 | Control Gap (invalid event ID) | Remove those IDs; they are blocking-only entries and are never emitted as filterable events |
| Rule reads PowerShell script content while only module logging is enabled | Inconclusive (Logging Mode Mismatch) | Switch to the fields 4103 carries, or enable script block logging; the two channels do not substitute |
| Rule validates and converts but the converted query names no real channel | Control Gap (pipeline mapping) | Re-target the category or service the pipeline maps, then re-convert and inspect the output |
| Field the rule selects on is absent from that event ID's template | Control Gap (template mismatch) | Split the rule per event ID and use the field names that ID actually carries |
| Events exist on the host but not in the index | Inconclusive (Filtered Forwarding) | Report the forwarding subset as the reason and quantify the uncovered hosts before any clean verdict |

## Containment and Recovery

1. **Preserve the precondition evidence:** Save `auditpol` output, `sysmon -c` output and one raw event per ID with the rule. A later silence is otherwise unattributable to config or policy change.
2. **Treat logging gaps as their own incident item:** A disabled subcategory or omitted Sysmon event type is a visibility defect with an owner and a date, not a footnote on a clean verdict.
3. **Never hand-edit the converted query:** The pipeline regenerates it; a manual edit becomes a hidden second definition that diverges on the next conversion.
4. **Re-validate after any config or policy change:** GPO refresh and Sysmon config updates change what exists. Re-run the audit and config gates, then replay the rule against a fresh captured event.
5. **Verify with lineage, not just volume:** Confirm the rule fires on the intended parent-child shape in the replay rather than merely producing a non-zero count.
