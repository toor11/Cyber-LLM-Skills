# Verification Probes and Expected Differentials

> Sub-skill: [`azure-and-entra-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Grant inventory

```text
# Delegated grants, with the tenant-wide ones called out.
az rest --method get --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" \  # azure-and-entra-attacks: class 1 grant inventory
  --query "value[].{client:clientId,consent:consentType,scope:scope}" --output table
# Application-role assignments on a service principal.
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignments" \
  --query "value[].{resource:resourceDisplayName,role:appRoleId}" --output table
```

Expected differential: a `consent=Principal` with a narrow scope is the control; `consent=AllPrincipals` with a mail or directory scope is the finding, and the scope string names the exposure.

## Class 2 — Revocation latency probe

```text
# Record a token, disable nothing; instead read the resource's CAE capability and
# the client's token lifetime, which decide the window without touching accounts.
az rest --method get --url "https://graph.microsoft.com/v1.0/policies/tokenLifetimePolicies" \
  --query "value[].{name:displayName,def:definition}" --output json
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=displayName eq 'Office 365 Exchange Online'" \
  --query "value[].{id:appId}" --output table
```

Expected differential: a resource in the CAE-supported set with CAE-negotiated sessions shows a short effective window; a resource outside it shows the full token lifetime as the window.

## Class 3 — Token Protection enforcement

```text
az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].{name:displayName,state:state,session:sessionControls}" --output json \
  | jq -r '.[] | select(.session != null) | "\(.name) \(.session)"'
```

Expected differential: a policy enabling token protection on the sensitive app is the control; no session control on an app reachable from unmanaged devices is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
