# Detection Queries and Telemetry Artifacts

> Sub-skill: [`syslog-and-cloudtrail-stream-parsers`](SKILL.md) | Family: **Security Automation and Tool Development**

Batch-parse and control-plane detection artifacts owned by this slug. Confirm field names against the provider's current audit log schema before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `Records[]` length reconciled against an independent count | High | No batch was silently truncated to its first event |
| 2 | `eventTime` with an explicit offset, converted to UTC | High | The event is placed at the correct instant |
| 3 | `eventName` in the logging-control watch list | High | Someone changed visibility; this is the detection that must never be missed |
| 4 | Rejected-record counter above zero | Medium | Some records were unparseable; the pipeline has a data hole to disclose |
| 5 | CEF header field count matching the schema | High | Escaped delimiters were tokenized correctly |

## Detection Artifacts

```text
[syslog-and-cloudtrail-stream-parsers:rule-spec] iterate Records[] per file and reconcile the count before shipping
[syslog-and-cloudtrail-stream-parsers:filter-fp] zero records from a non-empty object is a read error, not an empty account
[syslog-and-cloudtrail-stream-parsers:correlate] eventTime + sourceIPAddress + userIdentity.arn identifies one control-plane action
```

CloudTrail batch parse with a reconciliation check (Windows PowerShell 5.1):

```powershell
$file = "C:\evidence\cloudtrail\2026\11\14\CloudTrail-demo.json.gz"
$raw  = [IO.Compression.GZipStream]::new(
          [IO.File]::OpenRead($file), [IO.Compression.CompressionMode]::Decompress)
$reader = [IO.StreamReader]::new($raw)
$doc = $reader.ReadToEnd() | ConvertFrom-Json
$reader.Dispose()
Write-Output "records=$($doc.Records.Count)"
```

Control-plane watch list as a query over the parsed output:

```powershell
$doc.Records |
    Where-Object { $_.eventName -in @('StopLogging','DeleteTrail','UpdateTrail','PutEventSelectors') } |
    Select-Object eventTime, eventName, eventSource, @{n='arn';e={$_.userIdentity.arn}}, sourceIPAddress |
    Format-Table -AutoSize
```

Identity projection that avoids copying attacker-shaped JSON:

```powershell
$first = $doc.Records | Select-Object -First 1
$identity = New-Object psobject -Property @{
    type    = $first.userIdentity.type
    arn     = $first.userIdentity.arn
    account = $first.userIdentity.accountId
    invoked = $first.userIdentity.invokedBy
}
$identity | ConvertTo-Json
```

CEF tokenization check — the header must split into exactly the schema's field count regardless of escaped pipes in values:

```powershell
$line = 'CEF:0|Acme|Proxy|1.0|1001|Blocked a\|b pattern|7|src=10.0.0.5 dst=10.0.0.9'
($line -split '(?<!\\)\|').Count
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Reconcile record counts per batch at ingest; a drop to zero is an outage, not a quiet period.
- Alert separately on logging-control events so a trail modification is never buried in general cloud noise.
