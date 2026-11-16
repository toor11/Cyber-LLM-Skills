# Verification Probes and Expected Differentials

> Sub-skill: [`aws-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Principal and edge inventory

```text
# Identity policies that grant the escalation primitives.
aws iam list-policies --scope Local --query 'Policies[].Arn' --output text \
  | tr '\t' '\n' | while read -r p; do
      aws iam get-policy-version --policy-arn "$p" --version-id "$(aws iam get-policy --policy-arn "$p" --query 'Policy.DefaultVersionId' --output text)" \
        --query 'PolicyVersion.Document' --output json \
      | jq -r --arg p "$p" 'select(.Statement[]?.Action|tostring|test("iam:PassRole|iam:CreatePolicyVersion|iam:AttachRolePolicy|iam:UpdateAssumeRolePolicy")) | $p'
    done
```

Expected differential: policies that grant these primitives with `Resource: "*"` are the chain candidates; policies scoped to named ARNs with conditions are controls.

## Class 2 — Reachability simulation

```text
# Baseline: can the starting principal do the target action?
aws iam simulate-principal-policy --policy-source-arn "$START_ROLE" \
  --action-names s3:GetObject --resource-arns "arn:aws:s3:::prod-secrets/x"
# Probe: can the role it can pass/assume do it?
aws iam simulate-principal-policy --policy-source-arn "$TARGET_ROLE" \
  --action-names s3:GetObject --resource-arns "arn:aws:s3:::prod-secrets/x"
```

Expected differential: `baseline: implicitDeny` with `probe: allowed` is the chain, and the report cites both evaluations plus the hop that connects them.

## Class 3 — Trust-policy conditions

```text
aws iam list-roles --query 'Roles[].RoleName' --output text | tr '\t' '\n' | while read -r r; do
  aws iam get-role --role-name "$r" --query 'Role.AssumeRolePolicyDocument' --output json \
      | jq -r --arg r "$r" 'select([.Statement[]?.Principal]|tostring|test("\\*|:root")) | "\($r) \(.Statement)"'
done
```

Expected differential: a `:root` or `*` principal with an `sts:ExternalId` or `aws:PrincipalArn` condition is scoped; the same without either condition is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
