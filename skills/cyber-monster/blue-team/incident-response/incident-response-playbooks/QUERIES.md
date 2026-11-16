# Evidence and Attestation Queries

> Sub-skill: [`incident-response-playbooks`](SKILL.md) | Family: **Incident Response**

Queries owned by `incident-response-playbooks`, grouped by the programme question they answer. These read the case record rather than the estate: they show whether severity was assigned against criteria, whether disruptive actions had authority, whether phases produced artefacts, and whether the review changed anything. Adapt table names to your case-management and ticketing systems.

## Class 1 — Severity assignment attestation

Expected hit: every incident with a severity, the published criterion it met, the assigner and the timestamp. An incident with a severity but no criterion cannot be judged for proportionality.

```sql
SELECT i.incident_id, i.opened_utc, i.severity, i.severity_criterion,
       i.assigned_by, i.assigned_utc,
       CASE WHEN i.severity_criterion IS NULL THEN 'unattested' ELSE 'ok' END AS state
FROM incidents i
WHERE i.opened_utc > current_date - interval '90 days'
ORDER BY i.opened_utc DESC;
```

False-positive note: a severity changed legitimately as facts developed is not a defect; the finding is a change with no recorded reason, which the `severity_criterion` column exposes.

## Class 2 — Authority for disruptive actions

Expected hit: an approver and a time for every isolation, revocation or shutdown, drawn from a matrix that predates the incident. Actions without an approval record are the ones that surface in review and litigation.

```sql
SELECT a.incident_id, a.action_utc, a.action_type, a.target, a.performed_by,
       a.approved_by, a.approved_utc,
       CASE WHEN a.approved_utc IS NULL THEN 'no_approval'
            WHEN a.approved_utc > a.action_utc THEN 'after_the_fact'
            ELSE 'ok' END AS state
FROM incident_actions a
WHERE a.incident_id = 'INC-2026-1114'
ORDER BY a.action_utc;
```

False-positive note: a standing delegation for out-of-hours coverage is a valid approval, but it must resolve to a named role holder in the case file; a bare role name is not an approval record.

## Class 3 — Phase completion artefacts

Expected hit: an artefact reference per completed phase. A phase marked complete with no artefact is reopened, not carried forward.

```text
phase_attestation:
  phase:            containment
  required_artefact: enforcing-layer state record plus failed egress attempt
  present:          <case path or identifier>
  expected:         every phase in {triage, containment, eradication, closure}
                    carries its required artefact before the next phase is claimed
  invalidating:     a status update, a chat message or a dashboard screenshot
                    offered in place of the artefact
```

False-positive note: the artefact may be held by a different team in a different system; absence from the case folder is not absence of the artefact, and the cross-reference should be recorded rather than the phase reopened prematurely.

## Class 4 — Notification clock state

Expected hit: trigger event, trigger timestamp, deadline, filing receipt and owner for each applicable regime. The clock that matters is the one whose trigger actually occurred.

```kusto
IncidentNotifications
| where CaseRef == "INC-2026-1114"
| extend DeadlineUtc = case(Regime startswith "NIS2", TriggerAtUtc + 24h,
                            Regime startswith "SEC", TriggerAtUtc + 4d,
                            Regime startswith "SOCI", TriggerAtUtc + 12h,
                            DeadlineUtc)
| project Regime, TriggerEvent, TriggerAtUtc, DeadlineUtc, FiledAtUtc, ReceiptId, Owner
| extend State = iff(isnotempty(FiledAtUtc) and FiledAtUtc <= DeadlineUtc, "met",
                iff(isnotempty(FiledAtUtc), "late", "open"))
```

False-positive note: a receipt identifier captured from an API that returned `202 Accepted` is not a filing; the `ReceiptId` must correspond to a final submission state before the obligation is recorded as met.

## Class 5 — Playbook currency

Expected hit: the version and last exercise date of the playbook in force at the time of the incident, and confirmation that the roles it names are occupied. A stale playbook explains gaps that would otherwise be read as failure.

```sql
SELECT p.playbook_id, p.version, p.last_exercised_utc,
       p.approver_role, o.holder_name, o.valid_from, o.valid_to,
       CASE WHEN o.holder_name IS NULL OR o.valid_to < i.opened_utc
            THEN 'vacant_or_expired' ELSE 'ok' END AS state
FROM playbooks p
LEFT JOIN role_holders o ON o.role = p.approver_role
JOIN incidents i ON i.incident_id = 'INC-2026-1114'
WHERE p.in_force = true;
```

False-positive note: a role held by a job title rather than a person is normal in small teams; resolve the title to its current holder before treating the slot as vacant.

## Class 6 — Review closure and remediation

Expected hit: every review action with an owner, a due date and a closure reference, and no action closed without a verifiable change. This is the class that distinguishes a programme from a document library.

```sql
SELECT r.action_id, r.incident_id, r.description, r.owner, r.due_utc,
       r.closed_utc, r.closure_ref,
       CASE WHEN r.closed_utc IS NOT NULL AND r.closure_ref IS NULL
            THEN 'closed_without_evidence' ELSE 'ok' END AS state
FROM review_actions r
WHERE r.incident_id = 'INC-2026-1114'
ORDER BY r.due_utc;
```

False-positive note: an action closed by a configuration change recorded in a change system will have its evidence there, not in the tracker; the cross-reference is the requirement, not a copy of the evidence.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- State beside each class which record system it reads, so a programme review is not answered from a system that only sees part of the response.
