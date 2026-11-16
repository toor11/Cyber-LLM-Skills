# Verification Probes and Expected Differentials

> Sub-skill: [`azure-and-entra-attacks-rbac-and-managed-identity`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Assignment scope inventory

```text
# Assignments sorted by scope depth, which is the first cut of the review.
az role assignment list --all --include-inherited \
  --query "sort_by([].{principal:principalName,role:roleDefinitionName,scope:scope}, &scope)" \

# Identity attachments: which resources carry this identity.
az identity list --query "[].{name:name,rg:resourceGroup,clientId:clientId}"
```

Expected differential: a role at `/subscriptions/...` is broad by construction; a role at a single resource path with no role-assignment write is the control.

## Class 2 — Federation-subject audit

```text
az identity federated-credential list --identity-name "$IDENTITY" --resource-group "$RG" \
  --query "[].{name:name,subject:subject,issuer:issuer,audience:audiences}"
```

Expected differential: a subject of `system:serviceaccount:<ns>:<sa>` with an explicit name is scoped; `system:serviceaccount:<ns>:*` is the wildcard finding, and the namespace's RBAC decides who can exploit it.

## Class 3 — Escalation-path check

```text
# Does any role reachable from the identity include role-assignment write?
az role definition list --query "[].{name:roleName,actions:permissions[].actions}" --output json \
  | jq -r '.[] | select((.actions|tostring)|test("Microsoft.Authorization/roleAssignments/write")) | .name'
```

Expected differential: a role with that action inside the identity's scope is the escalation primitive; without it the identity cannot widen its own access.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
