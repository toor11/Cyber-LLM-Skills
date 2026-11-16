# Operational Triage and Response Playbook

> Sub-skill: [`evidence-handling-and-chain-of-custody`](SKILL.md) | Family: **Incident Response**

Structured runbook for `evidence-handling-and-chain-of-custody`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- An incident may lead to legal action, regulatory notification, insurance claim or disciplinary process.
- An insider investigation has been formalised against a named individual.
- A legal hold notice is issued covering systems, mailboxes or endpoint data.
- A system must be rebuilt and its current state is the only record of the intrusion.
- A third party requests forensic artefacts or the organisation must demonstrate what it preserved.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Proceedings likely, host still running with relevant memory state | Evidentiary collection | Capture memory and live state first, then image the disk with a write blocker, then hash both |
| Proceedings unlikely but undetermined | Preserve to the evidentiary standard | Collect as if it may be used; the weaker standard cannot be upgraded later |
| Legal hold issued but retention jobs still deleting | Control Gap (hold not applied) | Suspend deletion in the retention engine for the covered categories and record the suspension time |
| Only screenshots, chat notes or vendor reports available | Inconclusive (Evidence Gap) | State exactly what cannot be attested, and collect what remains before it is lost |
| Image digest mismatches with a documented bad-sector list | Media condition, not tampering | Record the errors and scope all conclusions to the readable regions |
| Evidence requested for a system already rebuilt | Evidence Gap (unrecoverable) | Document the rebuild, its date, and who authorised it; do not present post-rebuild artefacts as pre-incident evidence |

## Containment and Recovery

1. **Decide the standard before the first action.** Name the authorising role, the proceeding the evidence may support, and therefore the collection standard. Every later step inherits this decision and cannot revise it.
2. **Sweep in volatility order.** Registers and cache, process and network state, temporary storage, disk, then remote logs and archival media. Record any deliberate omission, such as declining a memory capture on a production system, with its reason.
3. **Protect the original, analyse the copy.** Attach a write blocker, record its identity, image to a separate destination, and analyse only the verified copy on a sanitised host.
4. **Demonstrate integrity and handling together.** Source and copy digests compared at acquisition and re-verified at each access; a custody entry for every transfer with item id, parties and timestamps. Neither record replaces the other.
5. **Apply the hold to the systems that delete.** A hold notice that is not reflected in retention configuration leaves the deletion job running on schedule. Record which categories are suspended and which could not be.
6. **Document the limits of the evidence.** Bad sectors, encrypted regions, host-protected areas, agent gaps and refused captures each bound what can be claimed. Recording the limits is what makes the rest of the record credible.
