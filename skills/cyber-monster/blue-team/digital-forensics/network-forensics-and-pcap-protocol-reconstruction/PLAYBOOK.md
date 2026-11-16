# Operational Triage and Response Playbook

> Sub-skill: [`network-forensics-and-pcap-protocol-reconstruction`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `network-forensics-and-pcap-protocol-reconstruction`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `pcap protocol reconstruction`.
- Alert, hunt outlier, or review request matching `http reconstruct`.
- Alert, hunt outlier, or review request matching `smb session analysis`.
- A data-loss alert requires proof of exactly which bytes left the network.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Exported object whose length equals the declared `Content-Length` and whose SHA-256 matches a copy from the receiving endpoint | Confirmed Transfer | Scope every destination the same client contacted; the hash equality makes this defensible evidence |
| Exported object short of declared length by a fixed block, with a matching snaplen limit | Inconclusive (Capture Truncation) | Do not describe the object's full content; obtain the copy from the receiving endpoint or proxy cache instead |
| SMB write session with no corresponding file in the share listing | Inconclusive (Commit Unproven) | Check `$MFT` and the share audit for the same path before concluding the write succeeded |
| Object extracted only after the analyst supplied a `-d` mapping | Inferred Content | Label it as heuristic in the report and corroborate against a second reconstruction such as Zeek or NetworkMiner |
| High-rate long-label DNS with successful resolutions and a narrow authoritative set | Control Gap (Exfil Channel) | Preserve the query log and block the authoritative set; confirm with the resolver's own logs before naming an operator |

## Containment and Recovery

1. **Preserve before mutating:** hash exported objects alongside the capture, and record the `-d` mappings and dissection version used, because a later re-export with different settings produces a different object.
2. **Corroborate with the far end:** the strongest recovery action is obtaining the same object from the receiving endpoint or the proxy cache, so the hash comparison outlives the session.
3. **Scope by destination, not by file name:** an exfiltrated archive is rarely unique; the destination set is what tells you whether other hosts sent the same material.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
