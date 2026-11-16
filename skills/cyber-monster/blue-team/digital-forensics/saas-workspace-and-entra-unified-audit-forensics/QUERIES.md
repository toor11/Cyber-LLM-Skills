# Evidence Extraction Artifacts and Queries

> Sub-skill: [`saas-workspace-and-entra-unified-audit-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `saas-workspace-and-entra-unified-audit-forensics`. Each class names the audit stream, the query that extracts it, and the retention or completeness fact that must accompany any absence. `Search-UnifiedAuditLog` runs in Exchange Online PowerShell.

## Class 1 — Stream availability and retention arithmetic

Expected hit: unified audit ingestion enabled, and the window start's age in days set against the applicable retention for each licence class in scope.

```powershell
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
$start = (Get-Date).AddDays(-200)
"window_start=$start age_days=$([math]::Round(((Get-Date)-$start).TotalDays,1))"
```

False-positive note: ingestion can lag by minutes to hours, so a window ending at the present under-reports its own tail. End the query at least a few hours before the current time, or re-run later and diff.

## Class 2 — Full operation set with paging

Expected hit: a complete operation inventory for one user, paged past the per-call cap rather than truncated at a round number.

```powershell
$all = @()
do {
  $b = Search-UnifiedAuditLog -StartDate $start -EndDate $end -UserIds $user `
         -ResultSize 5000 -SessionId "ual-$user" -SessionCommand ReturnLargeSet
  $all += $b
} while ($b.Count -eq 5000)
$rows = $all | ForEach-Object { $_.AuditData | ConvertFrom-Json }
$rows | Group-Object Operation | Sort-Object Count -Descending | Select-Object Count, Name
```

False-positive note: a result count of exactly 5000 or 50000 is a cap, not a total. Any report that quotes such a number as a total is quoting the truncation.

## Class 3 — Session pivot across workloads

Expected hit: one row per `AADSessionId` with the operations sharing it, the time span, and the distinct client origins.

```powershell
$rows | Where-Object { $_.AppAccessContext.AADSessionId } |
  Group-Object { $_.AppAccessContext.AADSessionId } | ForEach-Object {
    [pscustomobject]@{   # one row per authentication session
      SessionId  = $_.Name
      Operations = ($_.Group.Operation | Sort-Object -Unique) -join '; '
      ClientIPs  = ($_.Group.ClientIP | Sort-Object -Unique) -join '; '
      FirstSeen  = ($_.Group.CreationTime | Sort-Object | Select-Object -First 1)
    }
  } | Sort-Object FirstSeen
```

False-positive note: linkable identifiers are missing from some aggregated and background records, so a session-only search under-counts. Add a second pass filtered on the suspect client IP to catch records the session filter dropped.

## Class 4 — Sign-in pair analysis

Expected hit: an interactive sign-in and a non-interactive sign-in sharing a `SessionId`, with different source networks inside roughly ten minutes.

```powershell
Get-MgAuditLogSignIn -Filter "createdDateTime ge $($start.ToString('s'))Z" |
  Select-Object CreatedDateTime, UserPrincipalName, AppId, IpAddress, SessionId, IsInteractive, Status
```

False-positive note: `UniqueTokenIdentifier` differs between the authorization code and the bearer token, so it will not link the two events. Use `SessionId` plus app, user and a short time window, and remember a `SessionId` can legitimately span many event pairs.

## Class 5 — Mailbox access completeness

Expected hit: `MailItemsAccessed` records with `MailAccessType` of `Bind` or `Sync`, `OperationCount`, and the folder set, for each mailbox in scope.

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end -UserIds $user -Operations MailItemsAccessed `
  -ResultSize 5000 | ForEach-Object { $_.AuditData | ConvertFrom-Json } |
  Select-Object CreationTime, Operation, @{n='Type';e={$_.OperationProperties[0].Value}},
                @{n='Count';e={$_.OperationProperties[1].Value}}, ClientIP, AppAccessContext
```

False-positive note: `MailItemsAccessed` is a mailbox-auditing action whose retention follows the mailbox owner's licence, so a non-E5 mailbox older than 180 days is out of coverage regardless of what the tenant's other users retain.

## Class 6 — Persistence written into the tenant

Expected hit: inbox rules, mailbox forwarding, delegation and consent grants, each tied to a session or an origin network.

```powershell
Search-UnifiedAuditLog -StartDate $start -EndDate $end -UserIds $user `
  -Operations New-InboxRule,Set-InboxRule,UpdateInboxRules,Set-Mailbox,Add-MailboxPermission,Add-RecipientPermission `
  -ResultSize 5000 | ForEach-Object { $_.AuditData | ConvertFrom-Json } |
  Select-Object CreationTime, Operation, ClientIP, @{n='Parms';e={$_.Parameters}} |
  Format-List
```

False-positive note: Outlook desktop uses `UpdateInboxRules` with a different parameter shape than `New-InboxRule` from PowerShell or Outlook on the web. Read `Parameters` or `OperationProperties` according to the operation, not a single fixed field.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the retention arithmetic, the licence class per mailbox, and whether results were paged, beside every SaaS audit finding.
