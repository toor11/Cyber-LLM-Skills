# Operational Triage and Response Playbook

> Sub-skill: [`ics-and-ot-passive-network-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `ics-and-ot-passive-network-monitoring`. Paired offensive/mechanics reference: [`ics-ot-protocol-attacks`](../../../red-team/mobile-hardware-wireless-ics/ics-ot-protocol-attacks/SKILL.md).

## Triggers

- A source-destination pair issues a write, download, mode change, or restart that its communication matrix does not contain.
- An engineering host contacts PLCs it has never contacted, or contacts far more destinations than its role implies.
- A known process IP presents a new MAC, or a MAC appears under several addresses.
- A passive sensor or parser is deployed to a segment that previously had no coverage.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Write or download from a source new to the destination, no covering work order, with a subsequent process-value change | Confirmed Malicious / Gap | Notify the process engineer, preserve the capture and the device's configuration state, and contain the source host on the IT side rather than touching the controller |
| Same action covered by a work order whose scope lists the pair and the action | Benign Baseline (Scheduled Change) | Record the work order ID against the event and update the matrix if the change is permanent |
| Write from a pair that has always written, at its normal cadence | Benign Baseline (Normal Control Traffic) | Take no action; the matrix already contains this behaviour and the rule should not have fired |
| Read-only function codes from a new source | Lead (Discovery Activity) | Enrich the source host in the asset inventory and check IT telemetry for the host before escalating further |
| Download-shaped event on a redundant controller at a fixed cadence from the primary | Benign Baseline (Controller Synchronisation) | Add the pair and cadence to the matrix with a note so the rule stops generating it |
| Action on a segment with no span port or an unparsed protocol | Inconclusive (Visibility Gap) | Do not infer; record the segment and the protocol as a coverage action with an owner |
| Baseline window contained no startup or maintenance period | Inconclusive (Baseline Coverage) | Re-learn the matrix across all operating modes before judging the action |

## Containment and Recovery

1. **Preserve before mutating:** keep the passive capture, the parser log extract, the device's current configuration or project file, and the work-order records; interacting with the device destroys the state that proves the change.
2. **Contain on the IT side of the boundary:** block or isolate the source workstation using IT controls, never by blocking traffic to a controller or changing a control loop's state, since an unexpected loss of communication can be more dangerous than the intrusion.
3. **Involve the process engineer before any device action:** restoring a previous logic version is a change with safety consequences and belongs to the plant's change process, not to the SOC.
4. **Improve the matrix rather than the threshold:** every resolved case updates the learned communication matrix with the observed behaviour and its rationale, which is how the rule stays quiet without losing the high-impact signal.
