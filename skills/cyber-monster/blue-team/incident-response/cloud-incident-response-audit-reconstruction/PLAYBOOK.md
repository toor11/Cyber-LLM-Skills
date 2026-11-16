# Operational Triage and Response Playbook

> Sub-skill: [`cloud-incident-response-audit-reconstruction`](SKILL.md) | Family: **Incident Response**

Structured runbook for `cloud-incident-response-audit-reconstruction`. Paired offensive/mechanics reference: [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md).

## Triggers

- A cloud incident requires a timeline for a regulator, an insurer, a customer or a board, and the raw exports have not been joined yet.
- A detection fired but the onset, the full action set or the actor identity is unestablished.
- Two analysts produced different sequences for the same window and the difference must be resolved.
- A preservation or legal-hold obligation attaches and the record set has to be frozen and reproducible.
- A containment action needs retrospective justification from the audit record.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Management events present, data events absent, and the incident is a data-theft question | Inconclusive (Data-Event Gap) | Freeze what exists, declare the read scope unreconstructable from logs, and pivot to bucket and network substitutes |
| Same request id appearing twice with different delivery times | Baseline duplication (org and account trail) | Deduplicate on request id before any count, then rebuild the ordering |
| Distinct session keys under one role with non-overlapping time clusters | Multiple actors or sessions | Separate narratives per session key; do not attribute one actor's actions to the role's owner |
| Burst of distinct operations returning `AccessDenied` from one session | Probing or under-scoped new principal | Check principal creation date; if new and owned, it is a deployment fault, not an intrusion |
| Trail `LatestDeliveryTime` hours behind the export time | Delivery lag, not cessation | Record the lag, re-export later, and label the tail interval as pending rather than empty |
| Every record attributable to a documented automation owner | Benign Baseline | Record the owner mapping and stop; the detection needs a principal-ownership exclusion, not an incident |

## Containment and Recovery

1. **Freeze inputs before analysis.** Export each table to a case directory, hash it, and record the export timestamp. An analysis performed on live tables cannot be reproduced after retention rolls, and the case loses its defensibility first and its accuracy later.
2. **Pin absolute time literals.** Replace every relative window with explicit UTC boundaries in the stored query text. A query using a rolling window re-executed next week returns a different result and invalidates the reconstruction.
3. **Join on identifiers, order on sessions.** Use request id, correlation id or session access key to relate records; order the output by session then time. State both in the output so a reviewer can see the ordering basis.
4. **Label every gap with a cause.** Not collected, not retained, logging stopped, delivery pending. An unlabelled gap is read as absence of activity, which is the one conclusion the record cannot support.
5. **Keep the two clocks.** Where two sources describe one action, retain both timestamps and the source name rather than reconciling them into one. Reconciliation is an interpretation and must be separable from the record.
6. **Hand over with the query set, not the narrative.** The deliverable is the frozen inputs, the query text, the ordering rule and the timeline — in that order. A narrative without its queries cannot be defended, and a reviewer who cannot re-derive the ordering will assume it was chosen to fit a conclusion.
