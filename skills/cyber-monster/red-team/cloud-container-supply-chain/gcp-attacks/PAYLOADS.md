# Verification Probes and Expected Differentials

> Sub-skill: [`gcp-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Policy hierarchy inventory

```text
# Effective policy for one resource, then walk up the hierarchy.
gcloud projects get-iam-policy "$PROJECT" --format=json \
  | jq -r '.bindings[] | "\(.role) \(.members|join(","))"'
gcloud resource-manager folders get-iam-policy "$FOLDER" --format=json 2>/dev/null | jq -r '.bindings[].role' | sort -u
gcloud organizations get-iam-policy "$ORG" --format=json 2>/dev/null | jq -r '.bindings[].role' | sort -u
```

Expected differential: a role that appears only at project scope is scoped; the same role inherited from the organisation applies to every project, and the report names the inheritance point.

## Class 2 — Escalation-primitive probe

```text
# Who holds the primitives that turn a role into more roles?
for r in roles/iam.serviceAccountUser roles/iam.serviceAccountKeyAdmin roles/iam.serviceAccountAdmin roles/resourcemanager.projectIamAdmin; do
  printf '%-45s ' "$r"
  gcloud projects get-iam-policy "$PROJECT" --flatten="bindings[].members" \  # gcp-attacks: class 2 escalationprimitive probe
    --filter="bindings.role=$r" --format="value(bindings.members)" | tr '\n' ' '
  echo
done
```

Expected differential: a principal holding `serviceAccountUser` on an account with `roles/owner` is the two-hop path; holding it on an account with a narrow role is the control.

## Class 3 — Key-creation constraint and federation conditions

```text
gcloud resource-manager org-policies describe iam.managed.disableServiceAccountKeyCreation \
  --organization "$ORG" --format=json 2>/dev/null || echo "constraint not set at org"
gcloud iam workload-identity-pools providers describe "$PROVIDER" \
  --workload-identity-pool "$POOL" --location global \
  --format="value(attributeCondition,oidc.issuerUri)"
```

Expected differential: `enforce: TRUE` at the organisation is the key-creation control; an `attributeCondition` that names a repository and ref is the federation control, while `true` or an empty condition is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
