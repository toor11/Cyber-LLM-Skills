# Operational Triage and Response Playbook

> Sub-skill: [`crisis-communication-and-escalation`](SKILL.md) | Family: **Incident Response**

Structured runbook for `crisis-communication-and-escalation`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- An incident reaches a severity that requires executive, board, customer or regulator notification.
- A legal, insurance or contractual obligation attaches a notification clock to an incident.
- A statement about the incident has already been made publicly or to a counterparty and must be maintained or corrected.
- Law enforcement engagement is being considered and the communication posture must be set before contact.
- A third party discloses an incident that affects your organisation and a response statement is required.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Applicable regime identified with a trigger timestamp and a deadline | Confirmed obligation | Record the trigger evidence, assign the filing owner, and set an internal deadline ahead of the external one |
| Draft statement cites a claim still marked `unverified` | Blocked statement | Hold release, mark the claim, and either confirm it or issue a qualified wording that does not assert it |
| Two statements assert opposite states with no correction on record | Inconsistency requiring correction | Issue an explicit correction citing the register change, rather than a silent restatement |
| A maintenance notice or supplier bulletin describing their own incident | Not this issue | Confirm which entity is the reporting party and which obligations attach to you |
| Exercise or tabletop produces the same records as a real event | Baseline (exercise) | Confirm against the exercise schedule and label the records before they enter the case file |
| Register or filing records unavailable after the fact | Inconclusive (Attestation Gap) | State that the communication cannot be attested; reconstruct from sent records and name the gap |

## Containment and Recovery

1. **Open the fact register before the first external word.** One line per claim, with evidence state, source, timestamp and owner. Every later statement is an extraction from it, and every correction becomes a register change rather than a reassessment of memory.
2. **Map the obligation clocks to their real triggers.** Awareness, discovery and materiality determination start different clocks. Document the interpretation relied on, with counsel, at the time of the first filing rather than afterwards.
3. **Separate the three statement classes.** Internal escalation may carry labelled uncertainty; external obligations and public statements may not. Approvals differ accordingly, and the class should be recorded on the statement itself.
4. **Diff before publishing.** Compare the new statement against everything already said to that audience. A correction that is not labelled as a correction is read as concealment, whatever its accuracy.
5. **Attest delivery, not authorship.** Keep the filing receipt, the provider message id, the signed bytes and the approval record. Four artefacts, four different questions, none substitutable.
6. **Close the loop with every audience.** An audience that received an interim notice receives the final state or an owned follow-up. The communication incident ends when the register shows no disclosed claim still unverified and no audience left on an interim statement.
