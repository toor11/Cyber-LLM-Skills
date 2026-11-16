# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`business-email-compromise-response`](SKILL.md) | Family: **Incident Response**

Verified entry points for the read-and-attest half of a BEC response. The collection steps below are non-destructive; the two revocation-capable cmdlets are shown with their confirmation behaviour so they are run deliberately rather than by reflex. Never invent parameters — check `Get-Help <cmdlet> -Full` on the installed module version, because Graph PowerShell parameter sets have changed across module majors.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ExchangeOnlineManagement` | `Get-InboxRule -Mailbox user@contoso.com -IncludeHidden -ErrorAction Stop` | Enumerate every rule including hidden and disabled ones; hidden rules are invisible to the user-facing client and are the actor's preferred location | Windows, Linux, macOS (PowerShell 7) |
| `ExchangeOnlineManagement` | `Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) -UserIds user@contoso.com -RecordType ExchangeAdmin -ResultSize 5000` | Pull the rule-management and mailbox-configuration audit records for one principal | Windows, Linux, macOS |
| `Microsoft.Graph` (Users.Actions) | `Revoke-MgUserSignInSession -UserId user@contoso.com -Confirm` | Invalidate refresh tokens and active sessions; the `-Confirm` prompt is intentional so the principal is verified before the call | Any host with Graph access |
| `Microsoft.Graph` (Identity.SignIns) | `Get-MgUserAuthenticationMethod -UserId user@contoso.com` then `Get-MgUserAuthenticationMicrosoftAuthenticatorMethod` | Enumerate registered factors to find the actor-added method before removal | Any host with Graph access |
| `Microsoft.Graph` (Applications) | `Get-MgOauth2PermissionGrant -Filter "principalId eq '<objectId>'"` | List delegated consent grants, including the `Mail.Read` and `offline_access` scopes that outlive a password reset | Any host with Graph access |
| `Az` / AWS CLI (cloud mail) | `Get-MgServicePrincipalOauth2PermissionGrant`, or `aws sesv2 list-email-identities` for the sending identity inventory | Confirm the parallel cloud mail path in hybrid estates | Any host |
| Microsoft Defender for Office 365 | `Get-QuarantineMessage -RecipientAddress user@contoso.com` and the ZAP / purge actions in the portal | Identify and retroactively neutralise actor-sent mail still sitting in recipient mailboxes | Cloud only |

## Minimal Script Shape

The shape below is a read-only collection run: it snapshots rules, consent grants and authentication methods to a timestamped folder and hashes them, so the case has evidence before anyone changes state. No revocation call is made.

```powershell
# bec-evidence-snapshot.ps1 - read-only; nothing in Exchange or Entra is modified.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Upn,
    [Parameter(Mandatory)][string]$OutDir
)

$ErrorActionPreference = 'Stop'
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$case  = Join-Path $OutDir "bec-$($Upn.Split('@')[0])-$stamp"
New-Item -ItemType Directory -Path $case -Force | Out-Null

# 1. Mailbox rules, hidden ones included. Disable in the portal, never delete first.
Get-InboxRule -Mailbox $Upn -IncludeHidden |
    Select-Object Name, RuleIdentity, Enabled, ForwardTo, RedirectTo, MoveToFolder, DeleteMessage, Description |
    Export-Csv (Join-Path $case 'inbox-rules.csv') -NoTypeInformation -Encoding utf8

# 2. Audit records for the dwell window.
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) `
    -UserIds $Upn -RecordType ExchangeAdmin -ResultSize 5000 |
    Select-Object -ExpandProperty AuditData |
    Out-File (Join-Path $case 'exchange-admin-audit.json') -Encoding utf8

# 3. Registered authentication methods and consent grants.
$userId = (Get-MgUser -UserId $Upn).Id
Get-MgUserAuthenticationMethod -UserId $userId |
    Select-Object Id, AdditionalProperties |
    ConvertTo-Json -Depth 6 |
    Out-File (Join-Path $case 'auth-methods.json') -Encoding utf8

Get-MgOauth2PermissionGrant -Filter "principalId eq '$userId'" -All |
    ConvertTo-Json -Depth 4 |
    Out-File (Join-Path $case 'consent-grants.json') -Encoding utf8

# 4. Hash every artefact so later handling is provable.
Get-ChildItem $case -File | ForEach-Object {
    [pscustomobject]@{
        File   = $_.Name
        Bytes  = $_.Length
        SHA256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    }
} | Export-Csv (Join-Path $case 'SHA256SUMS.csv') -NoTypeInformation -Encoding utf8

Write-Host "Evidence collected to $case"
```

## Notes That Prevent Wrong Runs

- `Get-InboxRule` without `-IncludeHidden` returns only the rules the user-facing client would show. A rule the actor hid is invisible to that call, and reporting "no suspicious rules" from it is the single most common BEC misdiagnosis.
- `Search-UnifiedAuditLog` returns pages of up to 5,000 records and silently honours `-ResultSize` as a cap. A full page is a signal that more records exist; iterate with `-SessionId` and `-SessionCommand ReturnLargeSet` rather than trusting the first page.
- `Revoke-MgUserSignInSession` returns success on the request. The proof is a `Revoke` audit record plus absence of new sessions for that principal afterwards; keep the `-Confirm` prompt so the UPN is read back before the call.
- Consent grants are keyed by resource principal as well as client; filtering only on the user's object id misses tenant-wide grants that still confer mailbox access to the same application.
- Mailbox audit retention and unified audit log retention are configured separately and default differently by licence. Confirm both before promising a 90-day or 120-day timeline.
