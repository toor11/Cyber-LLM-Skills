# Verification Probes and Expected Differentials

> Sub-skill: [`aws-attacks-s3-and-storage`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Public-access and policy inventory

```text
# Account-level flags first: they override bucket policies.
aws s3control get-public-access-block --account-id "$ACCT" --output json 2>/dev/null \
  || echo "no account-level block (all four flags off by default)"
# Then per bucket.
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  printf '%-40s ' "$b"
  aws s3api get-public-access-block --bucket "$b" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null || echo "none"
done
```

Expected differential: all four flags `true` at the account level is the control for every bucket below it; `none` means each bucket policy is live.

## Class 2 — Unauthenticated read probe

```text
# One known key, no credentials.
curl -s -o /dev/null -w 'anon_get: %{http_code}\n' "https://$BUCKET.s3.$REGION.amazonaws.com/$KEY"
curl -s "https://$BUCKET.s3.$REGION.amazonaws.com/$KEY?acl" | head -20
```

Expected differential: `403` with `<Code>AccessDenied</Code>` is the control; `200` proves public read without any policy reading. The `?acl` response shows which grantee list is in play.

## Class 3 — Cross-account grant resolution

```text
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text | jq -r '
  .Statement[] | select(.Effect=="Allow")
  | "\(.Principal) \(.Action) orgid=\(.Condition.StringEquals."aws:PrincipalOrgID" // "NONE")"'
```

Expected differential: `orgid=NONE` on a grant to a foreign account is the cross-tenant finding; a value scopes it to the organisation.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
