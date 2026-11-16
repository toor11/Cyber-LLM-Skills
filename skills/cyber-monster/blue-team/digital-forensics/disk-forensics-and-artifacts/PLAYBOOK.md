# Operational Triage and Response Playbook

> Sub-skill: [`disk-forensics-and-artifacts`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `disk-forensics-and-artifacts`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

Disk evidence is the only evidence class that is both complete and fragile: complete because it holds everything the host ever wrote, fragile because every boot, every mount and every "quick look" changes it. The runbook therefore fixes the acquisition before it fixes the analysis, and it treats a failed verification as a re-acquire rather than a finding. When media is failing, the error map is part of the evidence and the analysis must state which sectors were unreadable, because conclusions drawn from a partial image are conclusions about the readable portion only.

## Triggers

- Alert, hunt outlier, or review request matching `disk forensics`.
- Alert, hunt outlier, or review request matching `disk image analysis`.
- Alert, hunt outlier, or review request matching `filesystem forensics`.
- Alert, hunt outlier, or review request matching `deleted file recovery`.
- A seized or returned device must be examined for what was stored, executed or removed.
- A server is being rebuilt and the volume must be preserved before the build starts.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Image hash matches acquisition hash and `fls` lists deleted entries with resolvable records | Evidence usable | Build the filesystem timeline in UTC, then hand extracted artifacts to the specific artifact skill |
| Image hash mismatch between acquisition and analysis copies | Inconclusive (Integrity Failure) | Stop, re-acquire from the source device, and record the failing step and tool version |
| Partition table damaged and the filesystem cannot be located at any plausible offset | Inconclusive (Structure Lost) | Report the unallocated-only finding; attempt recovery only on a copy and label anything found as fragments |
| Deleted file recoverable from an intact MFT record with resident data | Confirmed recovery | Hash the extracted record content and record the entry and sequence numbers |
| Deleted file name present but extent entries zeroed (ext4) | Partial recovery | Escalate to carving on a copy; do not describe the name alone as a recovered file |
| Volume appears as high-entropy data at the expected offset | Encrypted, not wiped | Check for a LUKS, BitLocker or APFS container header before drawing any conclusion |
| Evidence media reports read errors during acquisition | Hardware fault, not tampering | Preserve the error map beside the image hash and state which sectors were unreadable |

## Containment and Recovery

1. **Preserve before mutating:** power state, then memory, then the volume. A graceful shutdown flushes caches and updates filesystem metadata; a seized running host must be captured before any shutdown decision is taken by someone who does not know what is at stake.
2. **Verify before analysing, and re-verify before every session.** Store the image with its acquisition log and hash manifest, and re-run the hash at the start of each analysis session so a corrupted copy is caught before a conclusion is built on it.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and never reimage a host that holds the only copy of an artifact class (a domain controller's `NTDS.dit`, an HSM's logs) without an approved image first.
4. **Work from copies, always:** every extraction, carving run and mount happens against a copy of the image. The master image is opened read-only once, hashed, and stored; nothing writes to it, and no tool "repairs" it.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. Rebuild from known-good media rather than cleaning in place, and re-derive which other hosts share the compromised build so the same vector is closed everywhere.
