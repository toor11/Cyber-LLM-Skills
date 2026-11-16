# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`aws-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws iam simulate-principal-policy --policy-source-arn ARN --action-names ACTION --resource-arns ARN` | Whether one principal can do one action, using IAM's own evaluator | AWS CLI v2 |
| `aws` | `aws iam get-role --role-name R --query Role.AssumeRolePolicyDocument` | The exact trust conditions on a role | AWS CLI v2 |
| `aws` | `aws accessanalyzer list-findings --analyzer-arn ARN` | External-access findings the service already computed | AWS CLI v2 |
| `prowler` | `prowler aws --services iam s3 kms -M csv` | Bulk posture findings to seed the graph | Python |
| `pmapper` | `pmapper graph create --profile p && pmapper query 'who can do s3:GetObject with arn:aws:s3:::b/*'` | The reachability graph and the shortest path to an action | Python |

## Minimal script shape

```python
# Build the chain candidates from a role's grants, without executing anything.
import json
import subprocess

ESCALATION = ("iam:PassRole", "iam:CreatePolicyVersion", "iam:AttachRolePolicy",
              "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "sts:AssumeRole")

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def local_policies() -> dict[str, dict]:
    arns = sh("aws", "iam", "list-policies", "--scope", "Local",
              "--query", "Policies[].Arn", "--output", "text").split()
    out = {}
    for arn in arns:
        ver = sh("aws", "iam", "get-policy", "--policy-arn", arn,
                 "--query", "Policy.DefaultVersionId", "--output", "text").strip()
        out[arn] = json.loads(sh("aws", "iam", "get-policy-version", "--policy-arn", arn,
                                 "--version-id", ver, "--query", "PolicyVersion.Document",
                                 "--output", "json"))
    return out

def candidates(policies: dict[str, dict]) -> list[str]:
    hits = []
    for arn, doc in policies.items():
        for st in doc.get("Statement", []):
            actions = st.get("Action")
            actions = actions if isinstance(actions, list) else [actions]
            if st.get("Effect") == "Allow" and any(a in ESCALATION for a in actions):
                if st.get("Resource") == "*":
                    hits.append(arn)
    return hits

if __name__ == "__main__":
    print(candidates(local_policies()))
```

Each returned ARN is a policy that grants an escalation primitive on `*`; the report then names the role it is attached to and the target role it can reach.
