# Verification Probes and Expected Differentials

> Sub-skill: [`serverless-and-function-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Reachability inventory

```text
# Function URLs and their auth type.
aws lambda list-function-url-configs --function-name F 2>/dev/null | jq '.FunctionUrlConfigs[] | {url:FunctionUrl,auth:AuthType}'
# Every function with its role and environment keys (values are not printed).
aws lambda list-functions --query 'Functions[].{name:FunctionName,role:Role}' --output table
aws lambda get-function-configuration --function-name F --query '{env:Environment.Variables|keys,role:Role,timeout:Timeout}' --output json
```

Expected differential: `auth: NONE` on a URL is public invocation; `AWS_IAM` is the control. Environment keys named like secrets are the second finding, independent of the first.

## Class 2 — Unauthenticated invocation probe

```text
# One GET to the function URL, no signature. Do not target a function with side effects.
curl -s -o /dev/null -w 'anon_invoke: %{http_code}\n' "$FUNCTION_URL"
curl -s -o /dev/null -w 'signed: %{http_code}\n' --aws-sigv4 "aws:amz:$REGION:lambda" \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" "$FUNCTION_URL"
```

Expected differential: `anon_invoke: 403` is the control; `200` is the finding. Comparing with the signed request shows whether the authorisation is doing anything.

## Class 3 — Role scope audit

```text
aws iam list-attached-role-policies --role-name "$ROLE" --query 'AttachedPolicies[].PolicyName' --output text
aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames' --output text
aws iam get-role-policy --role-name "$ROLE" --policy-name "$P" --query PolicyDocument --output json | jq '.Statement[]|"\(.Action) \(.Resource)"'
```

Expected differential: actions limited to the resources the function uses is the control; `*` on a service or an `iam:`/`sts:` write action is the finding, and the policy name is the citation.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
