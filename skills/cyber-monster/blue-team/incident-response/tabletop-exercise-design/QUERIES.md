# Evidence Queries and Attestation Artifacts

> Sub-skill: [`tabletop-exercise-design`](SKILL.md) | Family: **Incident Response**

Attestation artefacts owned by `tabletop-exercise-design`. These are not SIEM queries — they are the records that let a facilitator, an auditor or a reviewer verify that an exercise tested what it claimed to test and produced work that is tracked. Each class names the artefact, the check that validates it, and the false-positive that makes a well-formatted exercise meaningless.

## Class 1 — Objective-to-inject traceability

Expected hit: a matrix in which every objective row has at least one inject, and every inject names the objective it forces. Objectives without injects were discussed, not tested.

```yaml
# ttx-traceability.yaml — the design record that must exist before conduct.
objectives:
  - id: OBJ-1
    statement: Decide isolation order for the ERP cluster versus customer notice.
    injects: [INJ-3]
    plan_reference: IRP v7.2 s4.2
  - id: OBJ-2
    statement: Establish the notification clock from an evidenced awareness time.
    injects: [INJ-5]
    plan_reference: DPA clause 9.3
injects:
  - id: INJ-3
    at: T+00:45
    forces_objective: OBJ-1
    conflict: operations isolation versus 72h contractual notice
  - id: INJ-5
    at: T+01:20
    forces_objective: OBJ-2
    conflict: no timestamped record of first awareness
```

False-positive note: an inject listed against an objective but never delivered during conduct appears traceable on paper. Compare the design record against the delivered-inject log before accepting the matrix.

## Class 2 — Delivered-inject and decision log

Expected hit: one row per inject actually delivered, with delivery time, the roles present, the decision taken and the information they had. This log is what the action items attach to.

```text
INJECT LOG — TTX-2026-04 (times relative to start, T+mm)

ID     T+      PRESENT              DECISION TAKEN                       BASIS CITED
INJ-3  00:45   COO, GC, IT-Dir      Isolate ERP after notifying tier-1    plan silent on order
INJ-5  01:20   GC, IR-Lead          Clock start unproven; escalating      no timestamped record
INJ-6  01:55   COO, Comms           Holding statement drafted, not sent   no approval path defined
```

False-positive note: a decision log written after the exercise from memory records the decision the group wishes it had made. Log live, during conduct, with the facilitator or a dedicated recorder.

## Class 3 — Plan-versus-practice gap evidence

Expected hit: for each finding, the specific plan text, or the specific missing artefact, that the inject exposed. A finding without a plan reference is an opinion.

```text
GAP RECORD — TTX-2026-04

G-01  Plan silent on isolation-versus-notification order.
      Evidence : IRP v7.2 s4.2 lists containment steps; no ordering statement.
      Impact   : Two roles believed they held the authority. Decision took 12 minutes.

G-02  Awareness timestamp not recordable from current tooling.
      Evidence : ticket system stores creation time only; chat has no server timestamp export.
      Impact   : Clock start cannot be evidenced; notification deadline is unprovable.

G-03  Customer notice clause unknown to responders.
      Evidence : DPA clause 9.3 (72h) not referenced in IRP appendix B.
      Impact   : Participants assumed statutory timeline only.
```

False-positive note: a gap attributed to "lack of training" is usually a gap in the plan, the tooling or the authority map. Push each finding until it names an artefact that could be changed.

## Class 4 — Missing-artefact inventory

Expected hit: the list of things the scenario needed that the organisation could not produce. This is often the most valuable output of a first exercise, and it is usually omitted from after-action reports because it embarrasses the organiser.

```text
READINESS ARTEFACT CHECK — produced during design, verified during conduct

Artefact                        Available?  Owner            Note
Current IRP, signed              yes         CISO             v7.2, 2026-03-14
Escalation contact list          partial     Service Desk     3 of 11 numbers stale
Network diagram, current         no          Infrastructure    last updated 2024
Customer notice clause register  no          Legal             clauses held per-contract only
Insurance notification contact   yes         Risk              broker contact current
Evidence storage procedure       no          IR                described verbally only
```

False-positive note: a document that exists but that nobody could locate during the exercise counts as unavailable. Record the search time, because that is the real readiness measure.

## Class 5 — Action tracking with verification

Expected hit: one row per finding, with a single accountable owner, a date, and a verification method that is a test rather than a document update. An action whose verification is "document updated" will be closed without changing anything.

```text
ACTION REGISTER — TTX-2026-04            (reviewed monthly; overdue escalates to CISO)

ID     Finding  Action                                              Owner        Due         Verify by
A-01   G-01     Add explicit ordering statement to IRP s4.2          IR-Lead      2026-12-15  Re-run INJ-3 in TTX-2027-01; decision under 3 min
A-02   G-02     Export server-side timestamps from chat platform     IT-Ops       2026-12-01  Produce a timestamp for a test message, with source
A-03   G-03     Add contractual notice clauses to IRP appendix B     Legal        2026-11-30  Clause 9.3 present and cited in a tabletop re-run
A-04   readiness Rebuild network diagram from live discovery        Infra        2027-01-31  Diagram diffed against a fresh scan, <30 days old
```

False-positive note: an action owned by a team rather than a person, or one with no verification test, will be reported complete on schedule without any change in capability. Both conditions are visible in this register and should be rejected at review.

## Deployment Gates

- Validate the design record against the delivered-inject log before circulating an after-action report; the two must agree.
- Require a verification method for every action at the point of creation, not at the point of closure.
- Keep the action register in the same system as ordinary engineering work so it competes for capacity and stays visible after the exercise's urgency fades.
