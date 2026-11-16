# Verification Probes and Expected Differentials

> Sub-skill: [`aws-attacks-iam-and-role-chaining`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Primitive inventory

```text
# The six escalation primitives, per policy, with their resources.
for p in $(aws iam list-policies --scope Local --query 'Policies[].Arn' --output text | tr '\t' '\n'); do
  v=$(aws iam get-policy --policy-arn "$p" --query 'Policy.DefaultVersionId' --output text)
  aws iam get-policy-version --policy-arn "$p" --version-id "$v" --query 'PolicyVersion.Document' --output json \
  | jq -r --arg p "$p" '.Statement[] | select(.Effect=="Allow") | select((.Action|tostring)|test("iam:PassRole|iam:CreatePolicyVersion|iam:AttachRolePolicy|iam:PutRolePolicy|iam:UpdateAssumeRolePolicy|iam:CreateAccessKey")) | "\($p) \(.Action) \(.Resource) \(.Condition // "no-condition")"'
done
```

Expected differential: lines with `Resource: "*"` and `no-condition` are the chain candidates; scoped ARNs with conditions are controls.

## Class 2 — Two-hop simulation

```text
aws iam simulate-principal-policy --policy-source-arn "$START" \
  --action-names iam:CreateFunction lambda:InvokeFunction --resource-arns "*"
aws iam simulate-principal-policy --policy-source-arn "$MIDDLE_ROLE" \
  --action-names s3:GetObject --resource-arns "arn:aws:s3:::prod-secrets/*"
```

Expected differential: `START` denied on the final action while `MIDDLE_ROLE` allowed, joined by a grant `START` holds on `MIDDLE_ROLE`, is the two-hop path.

## Class 3 — Trust-condition audit

```text
aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]' --output json \  # aws-attacks-iam-and-role-chaining: class 3 trustcondition audit
  | jq -r '.[] | select((.[1].Statement[]?.Principal|tostring)|test(":root|\\*")) | "\(.[0]) extid=\((.[1].Statement[]?.Condition."StringEquals"."sts:ExternalId") // "NONE")"'
```

Expected differential: `extid=NONE` on a role trusting a root principal is the finding; a value means the condition exists and the hop is scoped.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
