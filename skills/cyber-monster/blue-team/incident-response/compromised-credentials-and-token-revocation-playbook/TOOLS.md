# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`compromised-credentials-and-token-revocation-playbook`](SKILL.md) | Family: **Incident Response**

Verified revocation and verification entry points. The inventory and verification commands are read-only; the revocation cmdlets are shown with their confirmation surface. Never invent flags — `Reset-ADAccountPassword` parameter sets and Graph module cmdlet names have changed across versions, so confirm with `Get-Help <cmdlet> -Full`.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Microsoft Graph | `Revoke-MgUserSignInSession -UserId <upn> -Confirm` | Invalidate refresh tokens and active sessions at the issuer; the first token action in the sequence | Any host with Graph access |
| Microsoft Graph | `Get-MgUserAuthenticationMethod -UserId <objectId>` | Enumerate registered factors, including the actor-added one that must be removed before restore | Any host with Graph access |
| `ActiveDirectory` module | `Reset-ADAccountPassword -Identity <sam> -Reset -NewPassword (Read-Host -AsSecureString)` | Reset an on-premises password independently of the cloud authority | Domain-joined Windows with RSAT |
| `ActiveDirectory` module | `Get-ADUser -Identity krbtgt -Properties PasswordLastSet, Created` | Confirm `krbtgt` reset history and spacing before and after the double reset | Domain-joined Windows with RSAT |
| `Get-WinEvent` | `Get-WinEvent -LogName Security -MaxEvents 500 -FilterXPath "*[System[(EventID=4724)]]"` | Read the password-reset events that attest the `krbtgt` double reset and its spacing | Windows |
| AWS CLI (`iam`) | `aws iam put-role-policy --role-name <role> --policy-name AWSRevokeOlderSessions --policy-document file://revoke.json` | Terminate assumed-role sessions by token issue time; the document uses `DateLessThan` on `aws:TokenIssueTime` | Any host with AWS credentials |
| Azure CLI | `az ad user revoke-sign-in-session --id <upn>` | Issuer-side revocation from a shell without the Graph PowerShell modules | Any host with Azure credentials |

## Minimal Script Shape

The shape below is a read-only plan renderer: it inventories the artefact chain for one principal and prints the ordered plan with the primitive per artefact. Nothing is revoked; the output is the document an approver signs before the sequence runs.

```powershell
# revocation-plan.ps1 - read-only. Builds the artefact chain and the ordered plan.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Upn,
    [Parameter(Mandatory)][string]$OutDir,
    [int]$MaxTicketLifetimeHours = 10
)

$ErrorActionPreference = 'Stop'
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$plan  = Join-Path $OutDir "revocation-plan-$stamp.json"
$user  = Get-MgUser -UserId $Upn -Property Id, UserPrincipalName, OnPremisesSyncEnabled

$artefacts = @(
    [pscustomobject]@{ Class='refresh_tokens'; Exists=$true
        Primitive='Revoke-MgUserSignInSession'; SurvivesPasswordReset=$true }
    [pscustomobject]@{ Class='device_prt'; Exists=[bool]$user.Id
        Primitive='revoke device registration'; SurvivesPasswordReset=$true }
    [pscustomobject]@{ Class='on_prem_password'; Exists=[bool]$user.OnPremisesSyncEnabled
        Primitive='Reset-ADAccountPassword plus sync'; SurvivesPasswordReset=$false }
    [pscustomobject]@{ Class='kerberos_tgt'; Exists=[bool]$user.OnPremisesSyncEnabled
        Primitive='krbtgt double reset'; SurvivesPasswordReset=$true }
)

$authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id |
    Select-Object -ExpandProperty AdditionalProperties

[pscustomobject]@{
    generated_utc          = $stamp
    principal              = $Upn
    hybrid                 = [bool]$user.OnPremisesSyncEnabled
    artefacts              = $artefacts
    registered_methods     = $authMethods
    krbtgt_spacing_hours   = $MaxTicketLifetimeHours
    order = @(
        'tokens_and_grants'
        'passwords_both_authorities'
        'device_trust'
        'krbtgt_double_reset_after_persistence_sweep'
    )
    exclusions_to_record = @('responder jump host', 'break-glass identity', 'backup service account')
    proof_required = @(
        'issuer revocation event naming the artefact'
        'failed re-use of the old artefact after the propagation window'
        'for krbtgt: two reset events spaced beyond the maximum ticket lifetime'
    )
} | ConvertTo-Json -Depth 6 | Tee-Object -FilePath $plan

Write-Host "Plan written to $plan - nothing was revoked."
```

## Notes That Prevent Wrong Runs

- `Revoke-MgUserSignInSession` returns success on the request, not on propagation. The attestation is a revocation audit record plus failed re-use; keep the `-Confirm` prompt so the wrong principal is not revoked during a fast sequence.
- Device PRT revocation is a separate action from user session revocation. A joined device that keeps its PRT re-establishes a session without an interactive sign-in, so the user revocation alone appears to fail.
- `krbtgt` requires two resets. The account holds a two-password history, so one reset leaves tickets signed with the previous key valid; space the pair beyond the configured maximum ticket or service ticket lifetime.
- If `krbtgt` has never been rotated in a domain, the first reset can surface legacy cipher dependencies and replication problems. Run the vendor reset script in its informational mode first and record the finding.
- Read-only domain controllers replicate `krbtgt` on their own schedule and need the reset handled separately; a writable-controller-only reset leaves RODC sites validating old tickets.
- `Reset-ADAccountPassword -Reset` does not require the old password, which is what makes it usable during an incident; but it does not revoke existing Kerberos tickets, so it is never the last step.
