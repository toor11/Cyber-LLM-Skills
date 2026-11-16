# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`github-actions-and-oidc-federation-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws iam get-role --role-name R --query Role.AssumeRolePolicyDocument` | The exact trust conditions, including `aud` and `sub` | AWS CLI v2 |
| `aws` | `aws iam list-open-id-connect-providers` | Which OIDC providers exist in the account | AWS CLI v2 |
| `gh` | `gh api repos/O/R/actions/permissions/workflow` | The repository's default token permission | GitHub CLI |
| `rg` | `rg -n "id-token:\s*write" .github/workflows/` | Where the token permission is granted | any |
| `az` | `az identity federated-credential list --identity-name I --resource-group R` | Azure-side subject conditions for the same review | Azure CLI |

## Minimal script shape

```python
# Flag OIDC trust policies whose subject is broader than one repository.
import json
import subprocess

SUB = "token.actions.githubusercontent.com:sub"
AUD = "token.actions.githubusercontent.com:aud"

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def audit() -> list[dict]:
    roles = json.loads(sh("aws", "iam", "list-roles", "--output", "json"))["Roles"]
    out = []
    for r in roles:
        doc = r["AssumeRolePolicyDocument"]
        for st in doc.get("Statement", []):
            cond = json.dumps(st.get("Condition", {}))
            if "token.actions.githubusercontent.com" not in cond:
                continue
            like = st.get("Condition", {}).get("StringLike", {}).get(SUB, "")
            eq = st.get("Condition", {}).get("StringEquals", {})
            out.append({
                "role": r["RoleName"],
                "sub_like": like,
                "aud_pinned": AUD in eq,
                "wildcard_repo": like.startswith("repo:") and "/" in like and like.split("/")[1].startswith("*"),
            })
    return out

if __name__ == "__main__":
    for row in audit():
        if row["sub_like"] or not row["aud_pinned"]:
            print(row)
```

`aud_pinned: False` or `wildcard_repo: True` is the finding; the `sub_like` string is what the fix replaces with an exact `StringEquals`.
