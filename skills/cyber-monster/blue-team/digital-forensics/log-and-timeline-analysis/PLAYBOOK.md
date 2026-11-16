# Operational Triage and Response Playbook

> Sub-skill: [`log-and-timeline-analysis`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `log-and-timeline-analysis`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

Timeline work is where an investigation's conclusions become defensible or become unfalsifiable. The two failure modes are symmetrical: a timeline built from mixed epochs produces a confident wrong order, and a timeline that omits its baseline produces a burst of ordinary activity presented as an intrusion. The runbook therefore requires three things before any sequence is asserted — a recorded normalisation per source class, a same-length baseline window, and an explicit statement of the tolerance within which the order holds.

## Triggers

- Alert, hunt outlier, or review request matching `timeline analysis`.
- Alert, hunt outlier, or review request matching `super timeline`.
- Alert, hunt outlier, or review request matching `log correlation`.
- Alert, hunt outlier, or review request matching `event sequencing`.
- Multiple sources disagree about what happened first, and the question is which record to trust.
- A report must state what was on the host before, during and after a window.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Two independent sources agree on order with an explicit tolerance, and one carries an ordered identifier | Confirmed sequence | Publish the window with the baseline beside it and the tolerance stated |
| Sources disagree by more minutes than their precision explains | Inconclusive (Clock Skew) | Read the time service log and boot records before choosing either source; state the skew you found |
| Timestamps render as plausible dates but sit a decade or three centuries off | Normalisation error | Re-derive the epoch for that source class and rebuild the export; do not publish the window |
| Identical timestamps across unrelated sources | Collapsed precision | Check the converter's output resolution; re-export from the source with its native precision |
| Incident window density far above the same-length baseline | Confirmed anomaly | Break the density down by source and by host before attributing it to any actor |
| Extraction report shows warnings for the artifacts in question | Inconclusive (Parser Coverage) | State the parser gap; corroborate from a source that was parsed successfully |
| A source needed for ordering was never collected | Inconclusive (Telemetry Gap) | Do NOT close as clean; record the missing source and what claim it would have supported |

## Containment and Recovery

1. **Preserve before mutating:** extract from images and log copies, never from live sources that are still being written, and keep the storage file so a second question does not require a second extraction against evidence that may have changed.
2. **Record the normalisation next to the finding.** Every published row should be traceable to a source, an epoch and a precision. A timeline whose conversion you cannot reproduce is not evidence.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and never let a timeline's conclusions drive containment of a shared service until the ordering has been confirmed against a second source.
4. **Feed the timeline back into scope:** once the sequence is fixed, re-derive which hosts, accounts and network paths were involved inside that window, and re-run the extraction against those hosts before closing the scope.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the weakness was missing or misconfigured logging, fix the source configuration and record the change, so the next investigation has the sources this one lacked.
