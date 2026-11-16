# Evidence and Attestation Queries

> Sub-skill: [`crisis-communication-and-escalation`](SKILL.md) | Family: **Incident Response**

Queries owned by `crisis-communication-and-escalation`, grouped by the communication question they answer. These are attestation queries: they show when an obligation clock started, whether a filing or notice was actually delivered, and whether two statements about the same fact contradict each other. They read the case register and the communication platform, not the endpoint estate. Adapt field names to your GRC, ticketing and mail systems.

## Class 1 — Obligation clock attestation

Expected hit: one row per regime with its trigger event, the timestamp of that trigger, the derived deadline and the owner. A regime with no trigger row has a deadline nobody can meet or prove.

```kusto
IncidentObligations
| where IncidentId == "INC-2026-1114"
| project Regime, TriggerEvent, TriggerAtUtc, DeadlineUtc,
          Owner, EvidenceRef
| extend HoursRemaining = datetime_diff('hour', DeadlineUtc, now())
| order by DeadlineUtc asc
```

False-positive note: a regime listed because it "might apply" is not an obligation; a placeholder row without `EvidenceRef` should be excluded from the deadline calculation rather than driving an early filing.

## Class 2 — Filing and notice delivery

Expected hit: a submission receipt or sent-message record with a UTC timestamp for every obligation and every audience. Authored-but-unsent is the failure mode this class exists to catch.

```kusto
CommunicationLog
| where IncidentId == "INC-2026-1114"
| where Direction == "outbound"
| project SentUtc, Audience, Channel, Subject, ApprovalId, DeliveryStatus, MessageId
| order by SentUtc asc
```

False-positive note: a message that failed delivery but shows a creation timestamp looks sent in most platforms; require `DeliveryStatus` rather than presence of a record before claiming notification.

## Class 3 — Claim provenance

Expected hit: each disclosed claim resolved to a fact-register entry with a `confirmed` state and a source. Claims without a matching entry are the ones that become corrections.

```sql
SELECT s.statement_id, s.issued_utc, s.claim_text,
       r.entry_id, r.evidence_state, r.source_ref, r.owner
FROM issued_statements s
LEFT JOIN fact_register r ON r.claim_id = s.claim_id
WHERE s.incident_id = 'INC-2026-1114'
  AND (r.entry_id IS NULL OR r.evidence_state <> 'confirmed');
```

False-positive note: a claim paraphrased from a confirmed entry will not string-match; join on the claim identifier that the drafter assigned, not on text similarity.

## Class 4 — Statement-to-statement consistency

Expected hit: no pair of statements asserting opposite states for the same claim without an intervening correction entry. This is the review question that decides whether the record reads as a correction or as concealment.

```sql
WITH ordered AS (
  SELECT claim_id, issued_utc, asserted_state,
         lag(asserted_state) OVER (PARTITION BY claim_id ORDER BY issued_utc) AS prior_state,
         lag(issued_utc)     OVER (PARTITION BY claim_id ORDER BY issued_utc) AS prior_utc
  FROM issued_statements
  WHERE incident_id = 'INC-2026-1114'
)
SELECT claim_id, prior_utc, prior_state, issued_utc, asserted_state
FROM ordered
WHERE prior_state IS NOT NULL
  AND prior_state <> asserted_state
  AND NOT EXISTS (
      SELECT 1 FROM corrections c
      WHERE c.claim_id = ordered.claim_id
        AND c.issued_utc BETWEEN ordered.prior_utc AND ordered.issued_utc
  );
```

False-positive note: a state legitimately changing as evidence arrives is not a contradiction, provided the correction is recorded; the query excludes those by design and should return only the silent reversals.

## Class 5 — Approval and authority attestation

Expected hit: an approval record naming the authorising role, timestamped before the issue time. An approval after the fact is a ratification and should be labelled as such.

```text
authority_attestation:
  question:      who authorised this statement, and when relative to issue?
  evidence:      approval workflow record with approver role and timestamp
  expected:      approval_utc < issued_utc for every outbound statement
  blind_spot:    verbal approvals leave no record; those must be reconstructed
                 as a written confirmation in the case file or treated as absent
```

False-positive note: delegated approval during out-of-hours coverage is legitimate but often recorded under a generic on-call role; resolve the role to a named individual in the case file rather than accepting the role alone.

## Class 6 — Audience coverage and follow-up

Expected hit: every audience that received an interim notice also received the final state, or has an owned follow-up. Coverage gaps are the second-order failure after the first statement.

```kusto
let notified = CommunicationLog
  | where IncidentId == "INC-2026-1114" and Direction == "outbound"
  | summarize stages = make_set(Stage) by Audience;
notified
| where stages !has "final"
| project Audience, stages
```

False-positive note: an audience that only needed the final notice will legitimately show one stage; check the audience's notification requirement before treating a missing interim as a gap.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record beside each class which authority's timestamp it relies on, because the obligation clock and the evidence clock are set by different parties and a filing is judged against the former.
