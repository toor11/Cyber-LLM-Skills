# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`aws-attacks-s3-and-storage`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws s3control get-public-access-block --account-id A` | The account-level flags that override every bucket policy | AWS CLI v2 |
| `aws` | `aws s3api get-bucket-policy --bucket B --query Policy` | The resource policy text, including conditions | AWS CLI v2 |
| `aws` | `aws s3api get-bucket-acl --bucket B` | The legacy ACL grantees, which the policy layer does not show | AWS CLI v2 |
| `aws` | `aws s3api get-bucket-encryption --bucket B` | Default encryption and whether a bucket key is used | AWS CLI v2 |
| `curl` | `curl -s -o /dev/null -w '%{http_code}' https://B.s3.R.amazonaws.com/K` | Whether an object is readable without credentials | any |

## Minimal script shape

```python
# Effective-public verdict per bucket, with the layer that decides it.
import json
import subprocess

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True).stdout

def verdict(bucket: str, account_flags: dict) -> dict:
    pol = sh("aws", "s3api", "get-bucket-policy", "--bucket", bucket, "--query", "Policy", "--output", "text")
    public_stmt = 0
    if pol.strip():
        doc = json.loads(pol)
        for st in doc.get("Statement", []):
            if st.get("Effect") != "Allow":
                continue
            if '"*"' in json.dumps(st.get("Principal", {})) and "aws:PrincipalOrgID" not in json.dumps(st.get("Condition", {})):
                public_stmt += 1
    overridden = bool(account_flags.get("RestrictPublicBuckets"))
    return {"bucket": bucket, "public_statements": public_stmt,
            "overridden_by_account_flag": overridden,
            "finding": public_stmt > 0 and not overridden}

if __name__ == "__main__":
    flags = json.loads(sh("aws", "s3control", "get-public-access-block",
                          "--account-id", "111122223333", "--output", "json") or "{}")
    flags = flags.get("PublicAccessBlockConfiguration", {})
    buckets = sh("aws", "s3api", "list-buckets", "--query", "Buckets[].Name", "--output", "text").split()
    for b in buckets:
        print(verdict(b, flags))
```

`finding: True` is the case where a public statement exists and no account flag neutralises it; `overridden_by_account_flag: True` is the non-finding you should record explicitly.
