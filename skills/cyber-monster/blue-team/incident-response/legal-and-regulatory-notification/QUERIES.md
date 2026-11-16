# Evidence Queries and Attestation Artifacts

> Sub-skill: [`legal-and-regulatory-notification`](SKILL.md) | Family: **Incident Response**

Queries owned by `legal-and-regulatory-notification`. Each class produces one dated, sourced fact that counsel needs: when awareness occurred, what was decided and when, whether the affected data carries an obligation, and which contractual deadline binds first. These are attestation queries, not detections.

## Class 1 — Awareness timeline reconstruction

Expected hit: five distinct moments with distinct source identifiers — alert, ticket, human acknowledgement, escalation, decision-maker notification. Different regimes key off different moments, so the set matters more than any single row.

```kql
let awarenessLookback = 30d;
let alertMoment = SecurityAlert
    | where TimeGenerated > ago(awarenessLookback)
    | project T=TimeGenerated, Moment="alert fired", Src=strcat("alert:",SystemAlertId), Actor="platform";
let createdMoment = SecurityIncident
    | where CreatedTime > ago(awarenessLookback)
    | project T=CreatedTime, Moment="incident created", Src=strcat("incident:",ProviderIncidentId), Actor=Owner.assignedTo;
let modifiedMoment = SecurityIncident
    | where LastModifiedTime > ago(awarenessLookback)
    | project T=LastModifiedTime, Moment="incident last modified", Src=strcat("incident:",ProviderIncidentId), Actor=LastModifiedBy;
union alertMoment, createdMoment, modifiedMoment
| top 50 by T asc
```

False-positive note: automated enrichment and re-scoring update the incident record constantly, so "last modified" is not acknowledgement. Corroborate the human moment against a message or bridge record with a named participant.

## Class 2 — Decision record attestation

Expected hit: a dated record naming the decision, the evidence considered and the decision owner. An empty result is itself the finding — it means no determination exists and no clock keyed to that determination can be asserted.

```spl
index=governance sourcetype="governance:decision" earliest=-30d@d latest=@d
| search case_id="IR-2026-0417"
| eval has_evidence=if(isnotnull(evidence_refs),"yes","no"), has_owner=if(isnotnull(decision_owner),"yes","no")
| table _time, decision_type, decision_outcome, decision_owner, evidence_refs, has_evidence, has_owner
```

False-positive note: a decision recorded only as a chat message or a meeting minute may exist but not be in the governance index. Search the collaboration platform separately and record where the record was actually found, or state that it was not found anywhere.

## Class 3 — Obligation applicability by data category

Expected hit: a join between affected systems and the processing inventory showing whether a regulated category was reached. This answers "is this a personal data breach" far more reliably than asking whether data was taken.

```spl
index=cmdb sourcetype="cmdb:system" earliest=-1d@d latest=@d
| search incident_scope="yes"
| join system_id type=left
    [ search index=privacy sourcetype="privacy:ropa" earliest=-1d@d latest=@d
      | stats values(data_category) as categories, values(legal_basis) as bases,
              values(processor) as processors by system_id ]
| stats values(system_id) as systems, values(categories) as all_categories,
        values(processors) as all_processors by business_unit
| eval regulated=if(match(mvjoin(all_categories,","),"special category|financial|health|identity"),"YES","NO")
| table business_unit, regulated, all_categories, all_processors
```

False-positive note: a system can be in scope for the incident and hold no regulated data, while a downstream processor holds it. Walk one hop into processors before concluding the answer, and record the inventory's last-refresh date.

## Class 4 — Contractual deadline extraction

Expected hit: the notification clause and its measured deadline for each affected counterparty, with the clause reference. Contractual deadlines are frequently shorter than statutory ones and are missed because nobody looked.

```powershell
# Read-only listing of candidate agreements. Clause text must be read by a human.
Get-ChildItem -Path \\contracts\executed -Recurse -Include *.pdf,*.docx -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '(?i)msa|dpa|sow|bai|security' } |
    Select-Object -First 200 |
    Select-Object @{n='Contract';e={$_.Name}},
                  @{n='Path';e={$_.FullName}},
                  @{n='ModifiedUtc';e={$_.LastWriteTimeUtc}} |
    Export-Csv -NoTypeInformation .\contract-candidates.csv
```

False-positive note: filename matching is a lead generator, not an extraction. The deadline must be read from the clause text by a human and recorded with the clause number; a guessed "24 hours" is worse than no number.

## Class 5 — External submission receipt

Expected hit: the actual submission or acknowledgement record with its real timestamp, not the intended send time. A draft that was not filed discharges nothing.

```kql
let deliveryLookback = 30d;
let viaEmail = EmailEvents
    | where TimeGenerated > ago(deliveryLookback)
    | where Subject has_any ("notification","breach report","incident report")
    | where RecipientEmailAddress has_any ("regulator","authority","dfs.ny.gov","sec.gov")
    | project T=TimeGenerated, Channel="email", To=RecipientEmailAddress, Subject, DeliveryStatus;
let viaPortal = CloudAppEvents
    | where TimeGenerated > ago(deliveryLookback)
    | where ActionType has_any ("FileUploaded","FileSubmitted")
    | where ObjectName has_any ("notification","report","submission")
    | project T=TimeGenerated, Channel="portal", To=Application, Subject=ObjectName, DeliveryStatus="uploaded";
union viaEmail, viaPortal
| top 100 by T asc
```

False-positive note: internal circulation of a draft to counsel or the insurer produces the same subject lines. The recipient domain is the discriminator; verify it against the regulator's published submission channel rather than against a remembered address.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Record the inventory refresh date beside any data-scope join; a stale inventory converts a legal question into a guess.
- Store the awareness timeline in an immutable, access-controlled location with hashes. It will be requested by counsel, the insurer and possibly a regulator, and it must be identical each time it is produced.
