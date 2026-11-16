# Operational Triage and Response Playbook

> Sub-skill: [`network-detection-and-ids`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `network-detection-and-ids`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `network detection`.
- Alert, hunt outlier, or review request matching `ids rule`.
- Alert, hunt outlier, or review request matching `suricata`.
- Alert, hunt outlier, or review request matching `snort`.
- A flow-baseline outlier or a handshake-rarity hit from the baseline branch.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Alert `sid` with flow record showing a completed bidirectional session to an external destination outside the estate's normal set | Confirmed Malicious | Preserve the PCAP slice and the `eve.json` records for the `flow_id`, pull the endpoint's process and DNS evidence for the same minute, then decide on egress block with the host owner |
| Rare JA4 plus inconsistent SNI, corroborated by endpoint telemetry showing the same process | Confirmed Malicious | Label the finding encrypted-traffic-only in the report, attach the endpoint process as the corroborating artefact, and add the fingerprint-plus-SNI pair to prevalence monitoring |
| Flow-baseline outlier whose volume is explained by a scheduled backup or replication job | Benign Baseline | Record the job and its window, then baseline excluding that window rather than excluding the destination |
| Signature absent on a protocol the engine reported as `app_proto: failed` | Inconclusive (Parser Gap) | Do NOT report clean; extract the flow, confirm the protocol by hand, and file the parser or port mapping gap |
| Capture-kernel drops above the agreed threshold in the window | Inconclusive (Sensor Drop) | Do NOT report clean; quantify the uncovered interval and widen the sensor or shorten the retention window before re-running |
| Traffic is TLS-terminated at a proxy and the fingerprint belongs to the proxy | Benign Baseline (attribution defect) | Restate the finding against the proxy, and move the client-side question to endpoint or proxy-side logs |

## Containment and Recovery

1. **Preserve the packet slice first:** Export the PCAP for the `flow_id` and the matching `eve.json` lines before any blocking change. Once a block is in place, reproducing the conversation becomes impossible.
2. **Contain at the narrowest effective layer:** A destination block at the egress proxy or firewall is reversible; a host isolation is not. Prefer the block when the destination is the confirmed constant, and isolate only when the host shows additional behaviour.
3. **Record what the sensor could not see:** Note drops, encryption and parser failures in the incident record so the next analyst does not read a later clean window as proof the activity stopped.
4. **Tune with the revision, not the signature:** When a rule is noisy, change the rule and bump `rev`, then re-run the baseline. Suppressing by `sid` alone loses the ability to tell a fixed rule from a silenced one.
5. **Verify after containment:** Re-run the same query over the post-block window and confirm the specific `flow_id` pattern has stopped, rather than confirming that all alerts for the destination stopped.
