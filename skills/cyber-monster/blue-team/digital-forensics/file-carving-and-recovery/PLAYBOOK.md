# Operational Triage and Response Playbook

> Sub-skill: [`file-carving-and-recovery`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `file-carving-and-recovery`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

Recovery requests arrive late, after a device has been used, imaged again, or partially overwritten, and the honest answer is frequently "the region that held it has been reused". The runbook therefore front-loads two things: a decision about whether metadata recovery can answer the question without carving, and a measured false-positive rate for whatever carver you use. Without those two, a recovery report becomes a list of file-shaped byte ranges presented as evidence.

## Triggers

- Alert, hunt outlier, or review request matching `file carving`.
- Alert, hunt outlier, or review request matching `deleted file recovery`.
- Alert, hunt outlier, or review request matching `data carving`.
- A user deleted something material and the question is whether it is recoverable.
- An attacker removed staging, tooling or exfiltration archives before the host was seized.
- A volume was reformatted or partially overwritten and the question is what survived.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Deleted NTFS record with intact resident `$DATA` | Confirmed recovery | Extract from the record, hash it, and record entry plus sequence numbers |
| Deleted record with non-resident data whose `$Bitmap` bits are still free | Probable recovery | Read the recorded clusters from the image copy and validate the extracted content |
| Name present in directory residue but extent entries zeroed | Partial (name only) | Carve the region for the content; report the name as context unless a byte range is corroborated |
| Carved candidate passes structural validation on two carvers and matches a reference hash | Confirmed artifact | Report with byte range, carvers and hashes; pivot to host or network evidence |
| Carved candidates numerous but none validate | Carver false positives | Report the measured baseline rate and stop citing the population as evidence |
| Region's clusters reallocated to another live file | Inconclusive (Overwritten) | State the overwrite explicitly; do not present the current owner's bytes as the deleted file |
| Container header present with high-entropy payload | Inconclusive (Encrypted) | Record the container type and that carving cannot proceed past the header |

## Containment and Recovery

1. **Preserve before mutating:** image the volume before any recovery attempt, and carve from that image. Every write to the source — including a mount, a thumbnail cache, or a recovery tool that writes its index beside the data — reduces what remains recoverable.
2. **Stop using the host immediately.** Further use allocates clusters, and a cluster allocated is a cluster whose previous content is gone. Coordinate with the owner to take the device out of service before imaging.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and never reformat, reinstall or "clean" a device pending recovery without an approved image first.
4. **Recover to separate media:** carve to a dedicated output volume, keep the carver's audit file, and hash every candidate so two analysts can reach the same verdict from the same bytes.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the loss was caused by a missing backup or retention control, fix the control; if a deliberate wipe was the cause, treat the identity that ran the wipe as compromised and scope its other actions.
