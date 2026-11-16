# Evidence and Attestation Queries

> Sub-skill: [`insider-threat-investigation`](SKILL.md) | Family: **Incident Response**

Queries owned by `insider-threat-investigation`, grouped by the investigative question they answer. Each class measures a subject against their own history rather than against peers, and each states what its own coverage cannot show. Every query here is read-only, and every one is designed to be reproducible in a disciplinary or legal setting: source, window and coverage travel with the finding.

## Class 1 — Subject baseline construction

Expected hit: a per-subject baseline of access breadth, volume, working hours and destinations over a quiet period before the concern arose. Without this class, every later query is a comparison against a colleague, which is not evidence.

```sql
WITH prior AS (
  SELECT principal,
         date_trunc('week', ts) AS wk,
         count(*)                       AS events,
         count(DISTINCT object_id)      AS breadth,
         count(DISTINCT dest_host)      AS destinations
  FROM file_and_egress_audit
  WHERE ts BETWEEN now() - interval '180 days' AND now() - interval '28 days'
    AND principal = 'j.doe@contoso.com'
  GROUP BY principal, date_trunc('week', ts)
)
SELECT principal,
       avg(events)       AS mu_events,
       stddev(events)    AS sd_events,
       avg(breadth)      AS mu_breadth,
       max(breadth)      AS max_breadth,
       avg(destinations) AS mu_dest,
       count(*)          AS weeks_observed
FROM prior
GROUP BY 1;
```

False-positive note: a subject with fewer than eight observed weeks has a baseline too thin to score; report the observation count beside the deviation rather than presenting a ratio computed from three data points.

## Class 2 — Breadth and volume deviation

Expected hit: current-week breadth or volume outside the subject's own prior distribution, with the ratio and the observation count stated. Breadth is the stronger of the two, because volume alone rises with any bulk operation.

```sql
WITH base AS (
  SELECT avg(breadth) AS mu, stddev(breadth) AS sd
  FROM (
    SELECT date_trunc('week', ts) AS wk, count(DISTINCT object_id) AS breadth
    FROM file_audit
    WHERE principal = 'j.doe@contoso.com'
      AND ts BETWEEN now() - interval '180 days' AND now() - interval '28 days'
    GROUP BY 1
  ) w
),
probe AS (
  SELECT count(*) AS events, count(DISTINCT object_id) AS breadth
  FROM file_audit
  WHERE principal = 'j.doe@contoso.com' AND ts > now() - interval '7 days'
)
SELECT probe.events, probe.breadth, base.mu, base.sd,
       round((probe.breadth / nullif(base.mu, 0))::numeric, 2) AS breadth_ratio
FROM probe CROSS JOIN base;
```

False-positive note: a subject returning from leave compresses a month of normal work into one week; check the absence record before scoring the deviation.

## Class 3 — Destination novelty

Expected hit: an upload destination absent from the subject's historical destination set, joined to volume. This is the claim that converts a pattern into an exfiltration finding.

```sql
WITH history AS (
  SELECT DISTINCT dest_host
  FROM proxy_logs
  WHERE principal = 'j.doe@contoso.com'
    AND ts BETWEEN now() - interval '180 days' AND now() - interval '14 days'
)
SELECT p.ts, p.principal, p.dest_host, p.bytes_out, p.user_agent
FROM proxy_logs p
LEFT JOIN history h ON h.dest_host = p.dest_host
WHERE p.principal = 'j.doe@contoso.com'
  AND p.ts > now() - interval '14 days'
  AND p.bytes_out > 10000000
  AND h.dest_host IS NULL
ORDER BY p.bytes_out DESC;
```

False-positive note: a legitimate new SaaS rollout creates a first-use destination for everyone at once; check whether other users in the same team also show the destination as new before treating novelty as personal.

## Class 4 — Channel coverage beyond the network

Expected hit: collection through channels that never touch the proxy — removable media, print, clipboard, screenshots, cloud-sync clients. A case built only on proxy logs systematically under-reports collection.

```kusto
DeviceEvents
| where TimeGenerated between (ago(30d) .. now())
| where InitiatingProcessAccountUpn == "j.doe@contoso.com"
| where ActionType in ("UsbDriveMounted", "FileCreated", "PrintJobSubmitted",
                      "ClipboardDataCaptured", "ScreenshotTaken")
| summarize events = count(), first_seen = min(TimeGenerated),
            last_seen = max(TimeGenerated) by ActionType
| order by events desc
```

False-positive note: screenshots and clipboard events fire constantly during ordinary work; the finding is a change against the subject's own baseline for that action type, not the presence of the action.

## Class 5 — Legal hold effect attestation

Expected hit: a hold record plus retention configuration showing deletion suspended for the named categories on the named systems. This class decides whether the evidence still exists next month.

```text
hold_attestation:
  hold_id:            <identifier>
  custodians:         [subject, line manager, shared mailbox if applicable]
  categories:         [mail, file versions, endpoint telemetry, chat, backups]
  systems:            [mail platform, file service, EDR, SIEM, backup catalogue]
  suspended_verified: yes/no per system, with the configuration reference
  expected:           every listed system shows deletion suspended for the range
  invalidating:       a hold issued to people rather than to systems;
                      deletion continues on schedule and the record cannot tell
```

False-positive note: a system that retains by default for longer than the hold period needs no suspension, but the retention setting must still be recorded, or the case cannot show why it was safe to leave it alone.

## Class 6 — Fact and inference separation

Expected hit: each reported item tagged as observed (with artefact, source, window, coverage) or inferred (with the reasoning and what would disprove it). This is the class that makes the report usable by HR and defensible to a representative.

```text
report_item:
  claim:        "subject copied 4,120 documents in the final three weeks"
  class:        observed
  artefact:     file_audit rows, principal j.doe, window 2026-10-24..2026-11-14
  coverage:     file server audit enabled from 2026-04-01; excludes personal
                OneDrive sync, which is not logged by this source
  inference:    none
report_item:
  claim:        "subject intended to take the material to a competitor"
  class:        inference
  basis:        destination novelty plus departure date
  disproof:     a documented customer-migration project assigning that corpus
```

False-positive note: an inference that happens to be correct is still an inference; labelling it as observed is what damages the credibility of the observations beside it.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Confirm with counsel which of these classes may be run, on which principals, under the applicable monitoring notice, before any of them is executed.
