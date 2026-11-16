# Verification Probes and Expected Differentials

> Sub-skill: [`azure-and-entra-attacks-token-and-consent-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Consent-policy posture

```text
GET https://graph.microsoft.com/v1.0/policies/authorizationPolicy
# Fields that decide the branch:
#   defaultUserRolePermissions.permissionGrantPoliciesAssigned
#   defaultUserRolePermissions.permissionGrantPoliciesAssigned == [] => users may consent broadly
GET https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy
```

Expected differential: an empty `permissionGrantPoliciesAssigned` with no admin-consent policy is the enabling state; a low-risk policy plus `isEnabled: true` on the request policy is the control.

## Class 2 — Grant inventory

```text
GET https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'
# For each grant, resolve the client application's publisher verification state.
GET https://graph.microsoft.com/v1.0/servicePrincipals/$CLIENT_ID?$select=displayName,appId,verifiedPublisher,appOwnerOrganizationId
```

Expected differential: a grant whose `appOwnerOrganizationId` differs from the tenant and whose `verifiedPublisher` is empty is the illicit-consent shape.

## Class 3 — Consent audit trail

```text
GET https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDisplayName eq 'Consent to application'
# Report: initiatedBy, targetResources[].modifiedProperties (scope, consentType), createdDateTime
```

Expected differential: a consent event with `IsAdminConsent: true` and a mail or file scope is the finding; the same event for `User.Read` is a control.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
