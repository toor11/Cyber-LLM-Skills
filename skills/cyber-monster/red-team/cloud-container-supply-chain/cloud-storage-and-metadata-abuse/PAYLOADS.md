# Verification Probes and Expected Differentials

> Sub-skill: [`cloud-storage-and-metadata-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Anonymous-read probe

```text
# One request per object class, no credentials.
for u in "https://$BUCKET.s3.$REGION.amazonaws.com/$KEY" \
         "https://$ACCOUNT.blob.core.windows.net/$CONTAINER/$KEY" \
         "https://storage.googleapis.com/$BUCKET/$KEY"; do
  printf '%-90s ' "$u"
  curl -s -o /dev/null -w '%{http_code}\n' "$u"
done
```

Expected differential: `403` with an `AccessDenied` body is the control; `200` is the finding, and the same URL in a browser proves it without a client library.

## Class 2 — Signed-URL scope

```text
# Expiry and signed policy for every presigning call site.
rg -n --no-heading -B2 -A6 "generate_presigned_url|generate_presigned_post|sas|SignedUrl" -g '!test*'
# Azure: the SAS fields in use.
rg -n --no-heading "sig=|se=|sp=|sr=" -g '!test*'
```

Expected differential: an expiry in minutes with a single-object resource is the control; `ExpiresIn=315360000`, or a SAS with `sr=c` and no IP restriction, is the finding.

## Class 3 — Content classification

```text
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null | jq -r '.Statement[]|"\(.Principal) \(.Action)"'
aws s3api list-objects-v2 --bucket "$BUCKET" --max-items 5 --query 'Contents[].Key' --output text
```

Expected differential: object keys that read like `terraform.tfstate`, `backup-`, or `kms-` mean the bucket's classification is higher than a public-asset bucket, which sets the severity.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
