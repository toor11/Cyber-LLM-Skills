# Operational Triage and Response Playbook

> Sub-skill: [`network-forensics-and-pcap`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `network-forensics-and-pcap`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `network forensics`.
- Alert, hunt outlier, or review request matching `pcap analysis`.
- Alert, hunt outlier, or review request matching `packet capture forensics`.
- Alert, hunt outlier, or review request matching `flow analysis`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Endpoint pair whose byte volume and rank both shift against the matched baseline, with an unresolved destination and no proxy or update-feed ownership | Confirmed Malicious (traffic) | Preserve the capture and export the conversation for endpoint attribution; do not isolate on pcap alone until a host artefact agrees |
| Capture with a short snaplen or non-zero drops over the incident window | Inconclusive (Capture Gap) | State the bound explicitly; switch to flow records or endpoint telemetry rather than reporting a negative |
| Protocol absent from the hierarchy but present in firewall or proxy logs for the same window | Inconclusive (Observation Gap) | Re-check sensor placement, VLAN and asymmetric routing before treating absence as evidence |
| Half-open SYN pattern sourced from a documented scanner or health checker | Benign Baseline | Record the source in the scanner inventory; narrow exclusions by source address rather than disabling the check |
| Flow record and pcap byte counts diverging by an exact power-of-two factor | Sampling Artefact | Reconcile using the exporter's configured sampling rate before quoting either figure |

## Containment and Recovery

1. **Preserve before mutating:** copy the capture and its `capinfos` output with a hash, and record the sensor identity and position; a re-capture is never the same traffic.
2. **Contain on corroboration, not on volume:** a pcap can name a destination but not a process, so pair it with endpoint or proxy evidence before isolating a host.
3. **Close the collection gap:** if the capture could not answer the question, the recovery action is a snaplen and storage change on the sensor, scheduled so the next incident is answerable.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
