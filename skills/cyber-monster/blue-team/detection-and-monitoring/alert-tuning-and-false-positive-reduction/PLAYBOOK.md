# Operational Triage and Response Playbook

> Sub-skill: [`alert-tuning-and-false-positive-reduction`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `alert-tuning-and-false-positive-reduction`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- A rule's daily alert count exceeds what the queue can work, and analysts are closing alerts without writing a disposition.
- Analysts repeatedly write the same rationale ("backup window", "jump host", "scanner account") across unrelated cases.
- A rule has been disabled in production to silence it, with no recorded replacement.
- A new log source or agent rollout produces an alert burst that looks like a compromise but coincides with onboarding.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Dispositions exist for most alerts and one benign entity owns the bulk of false positives | Tuning Candidate | Mine the rationale, shadow-replay the narrow exclusion, re-fire the positive fixtures, then ship as one attributable change |
| Alerts carry no dispositions, or only free-text notes with no case link | Labelling Gap (Inconclusive) | Stop tuning; open a labelling sprint with a fixed window and a written rationale field before any filter is discussed |
| Rule fires only in a deployment window and stops without a code change | Benign Baseline (Onboarding or Deployment) | Record the change ticket, exclude by scheduled window rather than by entity, and re-check after the next deployment |
| Volume doubles after a forwarder or HEC change with no rule edit | Benign Baseline (Duplicate Ingestion) | Fix ingestion before tuning; compare alert counts per host and per source document, then re-baseline |
| Exclusion written but volume unchanged | Control Gap (Null-Keyed Predicate) | Audit null rates for every field in the predicate; a null-keyed exclusion suppresses nothing and must be corrected, not re-approved |
| Rule disabled to silence noise with no successor | Control Gap (Coverage Loss) | Treat as an outage of that technique; restore coverage with a narrowed rule before closing the ticket |
| Required channel disabled, rotated out, or never onboarded | Inconclusive (Telemetry Gap) | Do NOT close as clean; open a log-onboarding action and state which rule cannot be measured until it lands |

## Containment and Recovery

1. **Preserve before mutating:** export the pre-change rule text, the alert sample with dispositions, and the replay counts with SHA-256 hashes so the tune can be reversed and audited.
2. **Ship one lever per change:** separate the threshold change, the exclusion predicate, and the suppression window into distinct changes, each with its own shadow-replay numbers.
3. **Check blast-radius allowlists:** never suppress on a domain controller, a DNS resolver, a backup server, or a hypervisor management plane as a whole; name the specific service account and parent process instead.
4. **Carry the debt forward:** write the predicate, the rationale count, the accepted evasion margin, and a review date into the rule's documentation so the exclusion is revisited rather than inherited.
