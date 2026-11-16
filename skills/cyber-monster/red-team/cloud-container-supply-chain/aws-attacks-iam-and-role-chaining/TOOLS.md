# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`aws-attacks-iam-and-role-chaining`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws iam simulate-principal-policy` | The evaluator's own allow/deny for one principal and action | AWS CLI v2 |
| `pmapper` | `pmapper query 'who can do iam:PassRole with *'` | The reachability graph and the paths to an action | Python |
| `aws` | `aws iam get-policy-version --policy-arn A --version-id V` | The exact statement text, including conditions | AWS CLI v2 |
| `aws` | `aws organizations list-policies --filter SERVICE_CONTROL_POLICY` | SCPs that constrain every principal below an OU | AWS CLI v2 |
| `Cloudsplaining` | `cloudsplaining scan --input-file iam.json` | Ranks policies by escalation and data-exfiltration risk | Python |

## Minimal script shape

```python
# Two-hop chain finder over a role list; reports paths, executes nothing.
import itertools
import json
import subprocess

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def roles() -> dict[str, dict]:
    data = json.loads(sh("aws", "iam", "list-roles", "--output", "json"))
    return {r["RoleName"]: r for r in data["Roles"]}

def can_assume(role: dict, caller: str) -> bool:
    doc = role["AssumeRolePolicyDocument"]
    for st in doc.get("Statement", []):
        if st.get("Effect") != "Allow":
            continue
        principal = json.dumps(st.get("Principal", {}))
        if caller in principal or ":root" in principal or '"*"' in principal:
            cond = st.get("Condition", {})
            if "sts:ExternalId" not in json.dumps(cond):
                return True
    return False

if __name__ == "__main__":
    rs = roles()
    for a, b in itertools.permutations(rs, 2):
        if can_assume(rs[b], rs[a]["Arn"]):
            print(f"{a} -> {b} (no external id)")
```

Each printed pair is a hop an attacker holding the first role can take; the report then adds the final action that makes the hop matter.
