# Evidence Queries and Attestation Artifacts

> Sub-skill: [`ir-triage-and-timeline`](SKILL.md) | Family: **Incident Response**

Queries owned by `ir-triage-and-timeline`. Each class answers one attestation question that a triage timeline must close before scope can be stated: does the clock agree, did this value ever exist here before, do two planes place it at the same minute, was coverage continuous, and what did the principal actually do. Field names follow ECS or WinEventLog conventions; confirm against your own schema before deploying.

## Class 1 — Clock integrity and time base

Expected hit: every host inside the anchor slice reports a measured offset against the reference source, and the offsets are small enough that ordering is safe. An offset larger than the slice resolution invalidates any sequence built on that host.

```spl
index=wineventlog sourcetype="WinEventLog:System" SourceName="Microsoft-Windows-Time-Service" earliest=-24h@h latest=@h
| stats latest(Message) as last_msg, count as n by host
| eval clock_state=if(match(last_msg,"not synchronized|no valid time source"),"DRIFTED","SYNCHRONISED")
| table host, clock_state, n, last_msg
```

False-positive note: a host that syncs successfully every few hours still logs an occasional timeout; only a run of failures across the slice, or a `clock_state` of `DRIFTED` at the anchor, justifies treating that host's timestamps as unreliable.

## Class 2 — First-seen differential (endpoint and identity)

Expected hit: a small set of objects that exist in the probe window with zero occurrences in that host's or principal's own prior baseline. Rows are candidates; everything with prior history is the baseline.

```spl
index=edr sourcetype="edr:process" earliest=-2h@h latest=@h
| eval host=coalesce(host.name,ComputerName), obj=coalesce(process.path,NewProcessName)
| eval baseline_key=strcat(host,"|",lower(obj))
| lookup firstseen_baseline baseline_key OUTPUT prior_hits
| where isnull(prior_hits)
| stats min(_time) as first_seen, dc(user.name) as principals by host, obj
```

False-positive note: a freshly imaged host or a newly hired principal has no baseline by definition, so every object is first-seen. Require at least seven baseline days of coverage for the host or principal before scoring a row.

## Class 3 — Two-plane convergence at one minute

Expected hit: the same host and principal appear in two independently onboarded planes — process telemetry and authentication, or file creation and web request — inside one UTC minute. That agreement, not either row alone, is the anchor.

```spl
(index=edr sourcetype="edr:process" OR index=wineventlog sourcetype="WinEventLog:Security")
  earliest=-6h@h latest=@h
| eval host=coalesce(host.name,ComputerName), actor=coalesce(user.name,TargetUserName)
| eval minute_bucket=strftime(_time, "%Y-%m-%dT%H:%M")
| stats dc(sourcetype) as planes, values(src) as sources by minute_bucket, host, actor
| where planes >= 2
```

False-positive note: agent-side enrichment can stamp one event under two sourcetypes, which produces `planes=2` from a single source. Confirm the two rows carry different `host` or forwarder collection paths before calling it independent corroboration.

## Class 4 — Coverage continuity across the window

Expected hit: per-hour counts for the decisive channels that do not fall to zero mid-window. A zero-hour flanked by non-zero hours is a collection outage, not attacker quiet.

```kql
let winStart = ago(48h);
let winEnd = now();
union withsource=TableName SecurityEvent, DeviceProcessEvents, SigninLogs
| where TimeGenerated between (winStart .. winEnd)
| summarize Events = count() by TableName, bin(TimeGenerated, 1h)
| order by TableName asc, TimeGenerated asc
| extend PrevHour = prev(Events, 1), PrevTable = prev(TableName, 1)
| where Events == 0 and PrevHour > 0 and TableName == PrevTable
```

False-positive note: a legitimate bulk export or index maintenance window produces the same zero hour. Cross-check the collector's own health feed before treating a gap as evidence that something was hidden.

## Class 5 — What the principal actually did next

Expected hit: a post-access action that only makes sense once the session existed — a new mailbox rule, an OAuth consent, a service install, a share write — occurring after the sign-in and inside the dwell window. This converts "access happened" into "access was used".

```kql
let signinWindow = 7d;
let signin = SigninLogs
| where TimeGenerated > ago(signinWindow)
| project SessionAt = TimeGenerated, Principal = UserPrincipalName, SourceIp = IPAddress;
AuditLogs
| where TimeGenerated > ago(signinWindow)
| where OperationName in ("Add member to role.", "New-InboxRule", "Add service principal credentials.")
| join kind=inner signin on Principal
| where TimeGenerated between (SessionAt .. SessionAt + 2h)
| project SessionAt, TimeGenerated, Principal, OperationName, SourceIp
| order by SessionAt asc
```

False-positive note: an approved joiner-mover-leaver workflow or a documented automation principal produces the same operation-after-sign-in shape. Require the change ticket's actor or the automation's service principal to be excluded explicitly.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Record the clock offset, retention horizon and channel-enablement state beside every timeline you publish, so a reviewer can tell a measured zero from an assumed one.
- Document known management hosts, imaging workflows and automation principals before scoring first-seen rows.
