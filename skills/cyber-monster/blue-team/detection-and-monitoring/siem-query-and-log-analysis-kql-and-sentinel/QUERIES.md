# Detection Queries and Telemetry Artifacts

> Sub-skill: [`siem-query-and-log-analysis-kql-and-sentinel`](SKILL.md) | Family: **Detection and Monitoring**

KQL artifacts owned by `siem-query-and-log-analysis-kql-and-sentinel`. Table and column names are the Sentinel and Defender XDR schema as commonly onboarded; confirm against your own workspace schema before deployment, because custom tables and `_CL` suffixed tables differ per tenant. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Table, tier and freshness gate

Expected hit: each table present with recent data, and its tier known. A lake-only table is invisible to analytics rules, so the detection must move to a Defender-side rule or a scheduled job.

```kql
union withsource=TableName *
| where TimeGenerated between (ago(24h) .. now()) and isnotempty(TableName)
| summarize docs = count(), newest = max(TimeGenerated), oldest = min(TimeGenerated) by TableName
| extend lag_min = datetime_diff('minute', now(), newest)
| where lag_min > 60
```

```kql
// Usage and tier visibility for a suspect table (analytics tier only).
Usage
| where TimeGenerated between (ago(7d) .. now()) and DataType == "DeviceProcessEvents"
| summarize ingested_mb = sum(Quantity) by bin(TimeGenerated, 1d)
| sort by TimeGenerated asc
```

False-positive note: a table queryable in Advanced Hunting but absent from `Usage` is usually lake-only; confirm the tier in the Defender portal before concluding the ingestion broke.

## Class 2 — Aggregation with the entity preserved

Expected hit: per-entity counts at a stated grain, with the discriminating columns still present. Collapsing to a single total removes everything the finding needs.

```kql
DeviceProcessEvents
| where TimeGenerated between (ago(24h) .. now()) and FileName in~ ("rundll32.exe", "regsvr32.exe", "mshta.exe")
| summarize runs = count(), hosts = dcount(DeviceId), cmds = make_set(ProcessCommandLine, 5)
    by AccountName, FileName
| where hosts <= 2 and runs > 4
| extend runs_per_host = round(1.0 * runs / hosts, 1)
```

False-positive note: an installer or an admin script legitimately produces a small `make_set` of command lines on a few hosts; check whether the parent process is a known deployment tool before escalating.

## Class 3 — Join with an explicit kind

Expected hit: a left-outer join that preserves every row of the interesting side. The default `innerunique` de-duplicates the left side on the join key and undercounts silently.

```kql
let watch = _GetWatchlist('privileged_accounts') | project AccountUpn;
SigninLogs
| where TimeGenerated between (ago(24h) .. now()) and isnotempty(UserPrincipalName)
| join kind=leftouter watch on $left.UserPrincipalName == $right.AccountUpn
| extend is_privileged = isnotempty(AccountUpn)
| summarize attempts = count(), failures = countif(ResultType != 0) by UserPrincipalName, is_privileged
| where attempts > 0
| order by failures desc
```

False-positive note: `AccountUpn` casing differences between the watchlist and `SigninLogs` make an exact join miss; normalise with `tolower()` on both sides before concluding an account is unprivileged.

## Class 4 — Sequence with `serialize` and `prev()`

Expected hit: an ordered pair where the first event precedes the second for the same entity inside a bounded window. `summarize` cannot express this.

```kql
DeviceProcessEvents
| where TimeGenerated > ago(2d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| project DeviceId, AccountName, TimeGenerated, FileName, ProcessCommandLine
| sort by DeviceId, AccountName, TimeGenerated asc
| serialize
| extend prev_cmd = prev(ProcessCommandLine, 1), prev_dev = prev(DeviceId, 1)
| where prev_dev == DeviceId
| where ProcessCommandLine has_any ("-enc", "-e ", "FromBase64String")
    and prev_cmd has_any ("net user", "whoami", "systeminfo")
| project TimeGenerated, DeviceId, AccountName, prev_cmd, ProcessCommandLine
```

False-positive note: `serialize` depends on the surrounding `sort`; without the explicit `sort`, row order is not guaranteed and `prev()` returns an arbitrary neighbour.

## Class 5 — Field null-share before filtering

Expected hit: the null share for every field the filter depends on, so a filter that drops nulls is visible rather than silent.

```kql
SecurityEvent
| where TimeGenerated between (ago(24h) .. now()) and EventID == 4625
| summarize attempts = count(),
            null_user = countif(isempty(TargetUserName)),
            null_ip = countif(isempty(IpAddress)),
            null_logontype = countif(isempty(LogonType))
| extend null_user_pct = round(100.0 * null_user / attempts, 2)
```

False-positive note: `IpAddress` is legitimately empty for console logons; scope the null share to the logon types where the field is expected before treating it as a parser defect.

## Class 6 — Corroboration across planes

Expected hit: identity-plane and endpoint-plane tables agreeing on the same account and device inside one UTC minute. This is what turns an aggregate into proof.

```kql
let ids = SigninLogs
| where TimeGenerated between (ago(6h) .. now()) and ResultType == 0 and isnotempty(IPAddress)
| project Account = tolower(UserPrincipalName), id_time = TimeGenerated, ip = IPAddress;
DeviceLogonEvents
| where TimeGenerated between (ago(6h) .. now()) and isnotempty(AccountName)
| extend acct = tolower(AccountName)
| join kind=inner ids on $left.acct == $right.Account
| where abs(datetime_diff('minute', TimeGenerated, id_time)) <= 1
| project DeviceName, acct, LogonType, ip, id_time, TimeGenerated
```

False-positive note: a synchronised identity and endpoint event for the same user can also be a legitimate roaming logon; require the source address or the logon type to be anomalous before treating agreement as a finding.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record each table's tier beside the rule: an analytics rule on a lake-only table produces no alerts and no error.
