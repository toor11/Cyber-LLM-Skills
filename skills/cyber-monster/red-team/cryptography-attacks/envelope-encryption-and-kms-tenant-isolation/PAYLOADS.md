# Verification Probes and Expected Differentials

> Sub-skill: [`envelope-encryption-and-kms-tenant-isolation`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Context-binding probes

```text
# Compare the context at wrap and unwrap in the code path, and check what the
# service actually receives by logging only the key names, never the values.
rg -n --no-heading -A2 "generate_data_key|GenerateDataKey" -g '!test*'
rg -n --no-heading -A2 "\.decrypt\(|Decrypt\(" -g '!test*'
```

Expected differential: both call sites pass the same key set. A `generate_data_key` with a context and a `decrypt` without one is the portability finding.

```python
# Offline: does a wrapped DEK unwrap under a different context?
import boto3
from botocore.exceptions import ClientError
kms = boto3.client("kms", region_name="eu-west-1")
wrapped = open("dek.bin", "rb").read()
for ctx in ({"tenant": "A"}, {"tenant": "B"}, {}):
    try:
        kms.decrypt(CiphertextBlob=wrapped, EncryptionContext=ctx)
        print("UNWRAPPED under", ctx)
    except ClientError as exc:
        print("denied under", ctx, exc.response["Error"]["Code"])
```

Expected differential: a correctly bound DEK unwraps only under its own context and returns `InvalidCiphertextException` otherwise. Any other success is the finding.

## Class 2 — Policy-grant probes

```text
# Enumerate Allow statements that reach Decrypt, and their conditions.
aws kms get-key-policy --key-id "$KEK_ARN" --policy-name default --output text \
  | jq '.Statement[] | select(.Effect=="Allow") | select((.Action|tostring)|test("kms:(Decrypt|\\*)")) | {Principal, Condition}'
```

Expected differential: a grant with a `kms:EncryptionContext:` condition is bound; the same grant without one is the exposure.

```text
# Which principals can actually call Decrypt, from IAM's perspective.
aws iam simulate-principal-policy --policy-source-arn "$ROLE_ARN" \
  --action-names kms:Decrypt --resource-arns "$KEK_ARN"
```

## Class 3 — Rotation-version probes

```text
# Does the stored envelope carry a key version, and does the reader honour it?
rg -n --no-heading "key_version|keyVersion|kv\"|\"kid\"" -g '!test*'
```

Expected differential: a version field read before choosing the KEK is the control; a version present in the writer and ignored by the reader is a lifecycle defect.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
