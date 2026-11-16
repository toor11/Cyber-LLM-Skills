# Operational Triage and Response Playbook

> Sub-skill: [`legal-and-regulatory-notification`](SKILL.md) | Family: **Incident Response**

Structured runbook for `legal-and-regulatory-notification`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

This playbook assembles dated facts for counsel. It does not make the registrability decision and does not send external statements; those belong to counsel, the executive owner and crisis communication.

## Triggers

- An incident is confirmed and the question of external notification has been raised by anyone.
- Personal data, health data, financial data or government-marked data may be in scope.
- A contract, insurer or customer requires notice within hours of confirmation.
- A regulator, supervisory authority or sector body makes an information request.
- A public disclosure obligation may attach to a listed entity.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Regulated data category reached, awareness timestamp evidenced | Obligation Likely - Clock Running | Brief counsel immediately with the timeline package and the tightest applicable deadline |
| Regulated category unknown because the inventory is stale | Obligation Open | Refresh the scope join with the data owner; state the inventory date in every draft |
| Incident confirmed, no regulated data category reached | No Statutory Clock Identified | Document the assessment and its basis; check contractual deadlines separately |
| Materiality determination not recorded | Clock Not Started - Determination Missing | Escalate the governance gap; the delay in determining is itself reviewable |
| Contractual deadline shorter than any statutory one | Contractual Clock Binding | Notify per contract first; the statutory clock continues independently |
| Awareness timestamp has no artifact behind it | Inconclusive - Provenance Gap | Reconstruct from platform and ticket records before any deadline is quoted |
| Submission drafted but not filed | Obligation Outstanding | Distinguish draft from filing in every status report; a draft discharges nothing |

## Containment and Recovery

1. **Assemble the timeline before the meeting, not during it.** The awareness package — five moments with source identifiers, UTC and hash-sealed — is the single artefact every later conversation will reference. Producing it once, defensibly, prevents five contradictory versions.
2. **Run the clocks in parallel and name each one's owner.** Statutory, sector, contractual and insurer deadlines are different durations from different triggers. A tracker with one date on it guarantees at least one missed obligation.
3. **Route exfiltration facts, not exfiltration conclusions.** Counsel needs "transfer completed to an unsanctioned destination, classification unresolved" — not "data was stolen". Send the labelled fact and let the legal determination follow.
4. **Preserve the negative findings as carefully as the positive ones.** A documented assessment that a category was not reached is as important as one that was; it is the record that justifies not notifying.
5. **Keep drafting and filing strictly separate in status reporting.** Report the actual submission timestamp and receipt, never the intended one. The gap between a draft and a filing is where notification failures live.
