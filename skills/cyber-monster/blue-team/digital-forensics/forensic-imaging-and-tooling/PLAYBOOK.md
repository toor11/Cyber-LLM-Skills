# Operational Triage and Response Playbook

> Sub-skill: [`forensic-imaging-and-tooling`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `forensic-imaging-and-tooling`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

Acquisition is the one phase of an investigation that cannot be redone once the device leaves your control, and it is the phase most often performed under time pressure by someone who has not read the tool's log. The runbook's single aim is that the acquisition record answers, without you present, four questions: what was blocked, what was hashed and when, which format was used, and which regions could not be read. If the record answers those, the image can be defended; if it does not, the analysis built on it is provisional no matter how good the tooling was.

## Triggers

- Alert, hunt outlier, or review request matching `forensic imaging`.
- Alert, hunt outlier, or review request matching `write blocker`.
- Alert, hunt outlier, or review request matching `acquisition tooling`.
- Alert, hunt outlier, or review request matching `image verification`.
- A device must be imaged for a case that may reach a tribunal or a regulator.
- An existing acquisition is challenged, and the record must show whether it was sound.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Read-only state confirmed, blocker validated on scratch, hash pair present in the tool log | Sound acquisition | Verify the container, store with its log, and re-verify before each analysis session |
| Hash pair present but no blocker validation recorded | Control Gap | Re-acquire with a validated blocker, or document the software method and its test if re-acquisition is impossible |
| Hash mismatch between acquisition log and stored image | Inconclusive (Integrity Failure) | Do not analyse; investigate storage or copy error and re-acquire from the source if it survives |
| Failing media with a populated error map | Partial acquisition, scope known | Report the unreadable ranges as the coverage boundary; analyse only what was read |
| Logical acquisition used where physical was requested | Coverage Gap | State that unallocated space and slack are outside the image; re-acquire physically if the question needs them |
| Container opens but the verifier fails on one segment | Inconclusive (Container Damage) | Re-copy the failing segment from the original, then re-verify; do not analyse the damaged set |
| Device capacity smaller than the model's rated capacity | Possible hidden region | Record the reported capacity and query the drive for HPA or DCO configuration before analysis |

## Containment and Recovery

1. **Preserve before mutating:** capture volatile state first if the host is live, then acquire the media, then verify. The acquisition window itself must be recorded in UTC, because everything the image shows is only interpretable inside it.
2. **Acquire once, well.** A hurried acquisition performed twice produces two different records and a reviewer who cannot tell which is authoritative. Take the time to validate the blocker, record the identity, and keep the log.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and never power down a running system for imaging without the owner's agreement, since a graceful shutdown changes the very caches and timestamps the analysis may depend on.
4. **Store and re-verify:** keep the master image, its acquisition log, blocker record and hash manifest together on write-once or versioned storage, and re-verify before every analysis session and every transfer.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the acquisition was compromised by an unvalidated blocker or an unlogged tool, fix the process before the next case, not after.
