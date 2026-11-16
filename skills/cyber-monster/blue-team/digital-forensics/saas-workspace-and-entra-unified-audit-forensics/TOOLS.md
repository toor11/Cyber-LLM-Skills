# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`saas-workspace-and-entra-unified-audit-forensics`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for SaaS and identity audit extraction. Confirm parameter names with `Get-Help <cmdlet> -Full` on the installed module version; `Search-UnifiedAuditLog` and the Graph sign-in endpoints differ in their paging models.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Search-UnifiedAuditLog` | `Search-UnifiedAuditLog -StartDate <d> -EndDate <d> -UserIds <u> -ResultSize 5000 -SessionCommand ReturnLargeSet` | UAL extraction with paging past the per-call cap | Exchange Online PowerShell |
| `Get-AdminAuditLogConfig` | `Get-AdminAuditLogConfig -Property UnifiedAuditLogIngestionEnabled` | Prove the audit pipeline is switched on before interpreting any absence | Exchange Online PowerShell |
| `Get-MgAuditLogSignIn` | `Get-MgAuditLogSignIn -Filter "createdDateTime ge <iso>"` and `Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge <iso>"` | Interactive sign-in records with `SessionId` and network origin, plus consent grants on the Entra audit side | Microsoft Graph PowerShell |
| Office 365 Management Activity API | `GET /activities/audit/Content?contentType=Audit.Exchange` | Programmatic streaming export instead of scripted paging | Any HTTPS client |
| Defender advanced hunting / Sentinel lake | `DeviceLogonEvents` filtered on `Timestamp > ago(30d)`, then the lake equivalent | Endpoint-side correlation inside the same session window | Defender portal, Sentinel |
| Google Workspace Admin SDK | `GET /admin/reports/v1/activity/users/all/applications/login` | Admin, login and OAuth token audit on the Google side | Any HTTPS client |

## Minimal Script Shape

The shape below gates on ingestion and retention, pages past the cap, and emits one row per session with its operation set and distinct origins. Read-only.

```powershell
# ual-extract.ps1 — retention gate, complete paging, session pivot.
param(
  [Parameter(Mandatory)][string]$User,
  [Parameter(Mandatory)][datetime]$Start,
  [Parameter(Mandatory)][datetime]$End,
  [string]$OutDir = "C:\case\ual"
)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 0. Gate: pipeline on, window inside retention.
$cfg = Get-AdminAuditLogConfig
if (-not $cfg.UnifiedAuditLogIngestionEnabled) {
    "GAP: unified audit ingestion disabled -> INCONCLUSIVE" | Tee-Object "$OutDir\gate.txt"
    return
}
$ageDays = ((Get-Date) - $Start).TotalDays
"user=$User start=$Start age_days=$([math]::Round($ageDays,1))" | Tee-Object "$OutDir\gate.txt"
if ($ageDays -gt 180) {
    "WARNING: window exceeds 180-day Audit (Standard) retention; non-E5 records out of coverage" |
      Tee-Object "$OutDir\gate.txt" -Append
}

# 1. Page past the cap. A round number is a truncation, never a total.
$records = @(); $sid = "ual-$User-$(Get-Random)"
do {
    $batch = Search-UnifiedAuditLog -StartDate $Start -EndDate $End -UserIds $User `
               -ResultSize 5000 -SessionId $sid -SessionCommand ReturnLargeSet
    $records += $batch
} while ($batch.Count -eq 5000 -and $records.Count -lt 50000)

$rows = $records | ForEach-Object { $_.AuditData | ConvertFrom-Json }
"records=$($rows.Count)" | Tee-Object "$OutDir\gate.txt" -Append

# 2. Session-level output: the structure that separates replay from normal use.
$rows | Where-Object { $_.AppAccessContext.AADSessionId } |
  Group-Object { $_.AppAccessContext.AADSessionId } | ForEach-Object {
    [pscustomobject]@{
        SessionId  = $_.Name
        Operations = ($_.Group.Operation | Sort-Object -Unique) -join '; '
        Origins    = ($_.Group.ClientIP | Sort-Object -Unique) -join '; '
        FirstSeen  = ($_.Group.CreationTime | Sort-Object | Select-Object -First 1)
        LastSeen   = ($_.Group.CreationTime | Sort-Object | Select-Object -Last 1)
    }
} | Export-Csv "$OutDir\session_pivot.csv" -NoTypeInformation
```

## Notes That Prevent Wrong Runs

- `-SessionCommand ReturnLargeSet` raises the retrievable ceiling for a session; without it, repeated calls with the same session return the same first page rather than advancing.
- `UniqueTokenIdentifier` differs between the authorization code and the bearer token. Join on `SessionId`, then use app, user and a short time window as secondary conditions.
- Advanced hunting tables retain 30 days while a configured Sentinel data lake can hold years. A long-window query against the wrong store returns a false zero, and lake-only data is not visible to analytics rules.
- Export the raw `AuditData` JSON alongside any flattened table. The CSV columns are an index; the workload-specific fields live inside the JSON.
