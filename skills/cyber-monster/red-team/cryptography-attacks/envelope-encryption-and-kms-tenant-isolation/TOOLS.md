# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`envelope-encryption-and-kms-tenant-isolation`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws kms get-key-policy --key-id "$KEK_ARN" --policy-name default` | The exact grant set and conditions on the KEK | AWS CLI v2 |
| `aws` | `aws kms list-grants --key-id "$KEK_ARN"` | Temporary grants that bypass the key policy and are easy to forget | AWS CLI v2 |
| `aws` | `aws iam simulate-principal-policy --policy-source-arn "$ROLE" --action-names kms:Decrypt --resource-arns "$KEK"` | Whether a principal can unwrap, from IAM's own evaluator | AWS CLI v2 |
| `aws` | `aws kms describe-key --key-id "$KEK_ARN"` | Key manager, multi-Region status, and rotation state | AWS CLI v2 |
| `boto3` | `python -c "import boto3; print(boto3.client('kms').list_keys()[:3])"` | Confirms SDK credentials and Region before any probe | CPython |

## Minimal script shape

```python
# Enumerate the KEK's exposure: grants, policy conditions, and rotation state.
import json
import subprocess

def sh(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout

def exposure(key_arn: str) -> dict:
    policy = json.loads(sh("aws", "kms", "get-key-policy", "--key-id", key_arn,
                           "--policy-name", "default", "--output", "json"))["Policy"]
    doc = json.loads(policy)
    risky = [s for s in doc["Statement"]
             if s.get("Effect") == "Allow"
             and "kms:Decrypt" in json.dumps(s.get("Action"))
             and "kms:EncryptionContext:" not in json.dumps(s.get("Condition", {}))]
    meta = json.loads(sh("aws", "kms", "describe-key", "--key-id", key_arn, "--output", "json"))
    return {"unbound_decrypt_grants": len(risky),
            "multi_region": meta["KeyMetadata"].get("MultiRegion", False),
            "rotation": meta["KeyMetadata"].get("KeyRotationEnabled")}

if __name__ == "__main__":
    print(exposure("arn:aws:kms:eu-west-1:111122223333:key/abcd"))
```

A non-zero `unbound_decrypt_grants` is the finding; the rotation flag tells you whether a re-wrap is part of the fix.
