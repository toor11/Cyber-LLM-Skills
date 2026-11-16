# Operational Triage and Response Playbook

> Sub-skill: [`incident-response-playbooks`](SKILL.md) | Family: **Incident Response**

Structured runbook for `incident-response-playbooks`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- A detection or report requires classification as an event, an incident, or an investigation.
- An incident needs an assigned severity and the authority level that severity carries.
- A technique-specific playbook does not exist for the pattern being handled.
- A review or audit asks for evidence that a documented procedure was followed.
- A recurring alert indicates the current playbook is producing the wrong decision.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Confirmed destructive action or safety impact | Severity 1 | Incident commander assumes authority, notification set is activated, containment proceeds on the destructive clock |
| Confirmed intrusion without destructive action | Severity 2 | Security lead owns containment; evidence preservation precedes isolated remediation |
| Suspected intrusion, scope unknown | Severity 3 | On-call triage builds the timeline and reclassifies once scope is bounded |
| Alert investigated and explained with no impact | Event, not incident | Close with the explanation recorded; the playbook is not run, and the exclusion is evaluated |
| Disruptive action taken without an approval record | Control Gap (authority) | Document the gap in the case file immediately; do not manufacture a retroactive approval |
| Playbook approver role vacant at time of use | Control Gap (currency) | Record the vacancy as a finding and escalate to the role owner; proceed under the escalation path, not by improvising authority |

## Containment and Recovery

1. **Classify before acting.** Event, incident or investigation; then the severity criterion that was met. Every subsequent authority and notification choice derives from this and is unrecoverable if skipped.
2. **Run the specific playbook for the specific pattern.** The generic phases supply governance, not method. A technique-specific procedure produces the evidence classes and false-positive traps that the generic one cannot.
3. **Require an artefact per phase.** Triage produces a timeline with named sources; containment produces an enforcing-layer attestation; eradication produces a monitored window; closure produces owned actions with dates. A phase without its artefact reopens.
4. **Record authority at the moment of action.** Who approved the isolation, revocation or shutdown, and when, drawn from a matrix that existed beforehand. Out-of-hours delegation is legitimate when it resolves to a named holder.
5. **Start and record obligation clocks deliberately.** NIS2 runs from awareness, the SEC timeline runs from a materiality determination, SOCI sets a 12-hour critical threshold. Record the trigger relied on, with counsel, when the clock starts.
6. **Close on the remediation tracker.** The review is not the closure; the closure is each action having an owner, a date and a verifiable change. A programme whose reviews produce no tracked change is measuring its own paperwork.
