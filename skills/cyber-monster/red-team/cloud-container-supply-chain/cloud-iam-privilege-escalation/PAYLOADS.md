# Verification Probes and Expected Differentials

> Sub-skill: [`cloud-iam-privilege-escalation`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Primitive inventory per provider

```text
# AWS: policies granting the escalation primitives on a wildcard resource.
rg -n --no-heading "iam:(PassRole|CreatePolicyVersion|AttachRolePolicy|PutRolePolicy|UpdateAssumeRolePolicy|CreateAccessKey)" -g '*.json' -g '*.tf'
# Azure: assignment write and federated credential write.
az role assignment list --all --query "[?roleDefinitionName=='Role Based Access Control Administrator'].{principal:principalName,scope:scope}" -o table
# GCP: the impersonation and policy-write primitives.
gcloud projects get-iam-policy "$PROJECT" --flatten="bindings[].members" \  # cloud-iam-privilege-escalation: class 1 primitive inventory
  --filter="bindings.role:(roles/iam.serviceAccountUser OR roles/iam.serviceAccountAdmin OR roles/resourcemanager.projectIamAdmin)" \
  --format="value(bindings.role,bindings.members)"
```

Expected differential: a primitive on `*` or at subscription/organisation scope is a chain candidate; the same primitive on a named resource with a condition is the control.

## Class 2 — Evaluator confirmation

```text
# AWS: does the start principal reach the goal action directly?
aws iam simulate-principal-policy --policy-source-arn "$START" --action-names iam:AttachRolePolicy --resource-arns "$GOAL_ROLE"
# GCP: can the principal impersonate the goal account?
gcloud iam service-accounts get-iam-policy "$GOAL_SA" --format=json \
  | jq -r '.bindings[] | select(.role=="roles/iam.serviceAccountUser") | .members[]'
```

Expected differential: `allowed` for the start principal means a single hop and the finding is direct; `implicitDeny` means the path needs the intermediate node you then have to name.

## Class 3 — Path enumeration

```text
# Which principals can reach a role that holds an escalation primitive?
aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]' --output json \  # cloud-iam-privilege-escalation: class 3 path enumeration
  | jq -r '.[] | select((.[1].Statement[]?.Principal|tostring)|test("\\*|:root")) | .[0]'  # cloud-iam-privilege-escalation: class 3 path enumeration
```

Expected differential: a role with a wildcard or `:root` trust is an entry point; a role whose trust names one principal ARN with an external id is closed.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
