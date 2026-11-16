# Verification Probes and Expected Differentials

> Sub-skill: [`saas-oauth-app-and-m365-workspace-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Grant inventory

```text
az rest --method get --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" \
  --query "value[].{client:clientId,consentType:consentType,scope:scope}" --output tsv
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP/appRoleAssignments" \
  --query "value[].{role:appRoleId,resource:resourceDisplayName}" --output table
```

Expected differential: a `consent=Principal` with one scope is the control; `consent=AllPrincipals` with mail or file scopes is the finding, and the scope string is the exposure.

## Class 2 — Flow conformance

```text
# Capture the authorize request from the client and check four fields.
rg -n --no-heading "response_type|code_challenge|redirect_uri|response_mode" -g '!test*'
rg -n --no-heading "response_type=token|grant_type=password" -g '!test*' || echo "no implicit or password grant"
```

Expected differential: `code_challenge` present with an exact `redirect_uri` is the control; `response_type=token` or a missing PKCE parameter is the finding against RFC 9700.

## Class 3 — Mailbox configuration

```text
# Forwarding rules and delegates across the tenant, names only.
Get-Mailbox -ResultSize Unlimited | Get-InboxRule | Where-Object { $_.ForwardTo -or $_.RedirectTo } |
  Select-Object MailboxOwnerId, Name, ForwardTo, RedirectTo, Enabled
Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission |
  Where-Object { $_.AccessRights -contains "FullAccess" -and $_.User -notlike "NT AUTHORITY*" } |
  Select-Object Identity, User, AccessRights
```

Expected differential: no external `ForwardTo` and no unexpected `FullAccess` delegate is the control; either is the workspace finding, with the destination address as the evidence.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
