# Operational Triage and Response Playbook

> Sub-skill: [`tabletop-exercise-design`](SKILL.md) | Family: **Incident Response**

Structured runbook for `tabletop-exercise-design`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- An incident response plan has been revised and needs testing against the decisions it now claims to answer.
- A new threat class is in the news and leadership wants to know whether the organisation could respond.
- An exercise is due under a compliance or contractual obligation.
- A real incident revealed a decision failure and the fix needs validating before the next one.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Objectives written, injects mapped, plan revision named, safety rules agreed | Ready to Conduct | Schedule conduct, recorders and a hot wash immediately after |
| Objectives written but an inject delivers no decision | Design Gap | Rewrite the inject to force a choice between two legitimate obligations |
| Participants cannot engage because the scenario needs knowledge nobody holds | Design Failure | Simplify to a familiar threat class; the unfamiliar scenario is a second exercise |
| A live incident starts during conduct | Exercise Suspended | Run the incident; capture what the unplanned event revealed as a separate finding |
| A finding requires immediate real-world escalation | Escalate Now | Break scenario discipline; a readiness gap that is currently exploitable is not an action item |
| After-action report produced with no owners or dates | Incomplete | Do not close the exercise; register each finding with owner, date and verification |
| Action marked complete because a document was updated | Control Gap | Reopen; closure requires the verification test to pass |

## Containment and Recovery

1. **Write objectives before the scenario, and refuse to proceed without them.** An objective names the decision that would demonstrate the capability. Without it the exercise produces discussion, and discussion cannot be scored or improved.
2. **Design injects to create conflict between legitimate obligations.** The valuable findings come from isolation versus customer notice, transparency versus investigation integrity, speed versus evidence preservation. An inject that adds technical detail to an agreed story produces agreement.
3. **Record live, hot-wash immediately, and write the report from records rather than memory.** The conduct log is the evidence; the after-action report is its summary. Reversing that order produces a narrative that flatters the participants.
4. **Give every finding one accountable person, a date, and a verification test.** "Improve escalation" is not an action. "Produce a server-side timestamp for a test chat message by 1 December, verified by the IR lead" is.
5. **Close the loop by re-running the inject.** An action is complete when the re-run decision is faster, better evidenced or correctly escalated — not when the document was updated. Feed the re-run into the next exercise's objectives so improvement is continuous rather than annual.
