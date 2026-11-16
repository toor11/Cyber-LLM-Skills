# Detection Signals and Blue-Team Handoff

> Sub-skill: [`business-logic-flaws-workflow-and-state`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Workflow audit rows where an order or case status advances without the preceding required status event.
- Write requests carrying a `status`, `step`, or `state` field on endpoints that should derive it.
- Duplicate completion events for a one-time step sharing the same step token.
- Records found in a state absent from the application's documented transition table.
- A sequence of transition endpoint calls per session that violates the expected ordering.
- Payout, publish, or grant events whose gating step (KYC, payment, approval) has no matching completion record.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
