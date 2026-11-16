# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cloud-and-k8s-readonly-posture-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** boto3 with paginators and a read-only role; kubernetes Python client 30.x with `rbac_v1` and `core_v1` APIs.
- **Validation Gate:** `python -c "import boto3, kubernetes"` plus a dry collection against one account in read-only mode.
- Request only list/get verbs in the collection role; `*:Describe*` occasionally includes mutating operations on some services.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `aws cli` | `aws sts get-caller-identity` | Confirm which identity the collection is actually using | Cross-platform |
| `kubectl` | `kubectl auth can-i --list --as system:serviceaccount:default:default` | Enumerate effective permissions before asserting absence | Cross-platform |
| `boto3` | `python -c "import boto3; print(boto3.__version__)"` | Pin the SDK whose paginator names you rely on | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import boto3
from botocore.exceptions import ClientError

session = boto3.Session(profile_name="audit-readonly")
iam = session.client("iam")
rows, gaps = [], []
try:
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            rows.append({"arn": role["Arn"], "created": role["CreateDate"].isoformat()})
except ClientError as exc:
    gaps.append({"call": "iam:ListRoles", "code": exc.response["Error"]["Code"]})
print(json.dumps({"roles": len(rows), "gaps": gaps}))
```
