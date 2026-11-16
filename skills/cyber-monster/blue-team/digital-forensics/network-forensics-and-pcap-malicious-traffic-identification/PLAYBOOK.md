# Operational Triage and Response Playbook

> Sub-skill: [`network-forensics-and-pcap-malicious-traffic-identification`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `network-forensics-and-pcap-malicious-traffic-identification`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `malicious traffic analysis`.
- Alert, hunt outlier, or review request matching `c2 in pcap`.
- Alert, hunt outlier, or review request matching `exfil detection pcap`.
- A proxy or NGFW flags a periodic outbound session to newly registered or unclassified infrastructure.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Stable interval across three or more sessions, destination set rotating, byte ratio inverted versus the protocol's norm, plus an endpoint process event for the same client | Confirmed Malicious | Preserve the capture and the endpoint event together; scope every host resolving the same destination before containment |
| Interval stable but shared by the whole fleet, short sessions, tiny payloads, stable destination | Benign Baseline (Agent) | Record the fingerprint and destination as an approved agent baseline so the next hunt skips it |
| JA4 matches a published family but the destination is shared CDN space and no endpoint artefact agrees | Inconclusive (Corroboration Missing) | Do not block; hunt the endpoint side for a process that produced that ClientHello |
| One-directional capture making every ratio uncomputable | Inconclusive (Capture Gap) | Record the limitation and pivot to flow records or endpoint telemetry for volume evidence |
| Half-open pattern traced to a documented scanner or health checker | Benign Baseline | Add the source to the scanner inventory; narrow exclusions by source rather than disabling the check |

## Containment and Recovery

1. **Preserve before mutating:** copy the capture and record the sensor position, window and baseline used; the cadence statistic is not reproducible from a different window.
2. **Block the destination, not the address range:** CDN and cloud ranges will take unrelated services with them. Prefer an application-layer or DNS-level control scoped to the exact host or name.
3. **Rotate before eradicating:** if the beacon represents an active channel, treat every credential and token that host held as disclosed before rebuilding it.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
