# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`infrastructure-as-code-review`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `terraform` | `terraform plan -detailed-exitcode` | Drift and the exact diff, with an exit code for automation | Terraform 1.x |
| `terraform` | `terraform show -json` | Machine-readable plan for querying specific properties | Terraform 1.x |
| `checkov` | `checkov -d . --framework terraform --compact` | Declaration-level findings with resource addresses | Python |
| `tfsec` | `tfsec . --format json` | A second scanner, useful for corroboration rather than volume | Go binary |
| `conftest` | `conftest test plan.json -p policy/` | Rego policy over the plan, which catches module-default overrides | Go binary |
| `infracost` | `infracost breakdown --path .` | The cost of a change, which sometimes reveals an unintended resource class | Go binary |

## Minimal script shape

```python
# Report plan changes that touch security-relevant properties.
import json

SECURITY_KEYS = ("encrypted", "public", "acl", "policy", "ingress", "authoriz",
                 "deletion_protection", "versioning", "logging")

def risky(path: str) -> list[dict]:
    plan = json.load(open(path))
    out = []
    for rc in plan.get("resource_changes", []):
        change = rc.get("change", {})
        after = change.get("after") or {}
        touched = [k for k in after if any(s in k.lower() for s in SECURITY_KEYS)]
        if touched and change.get("actions") != ["no-op"]:
            out.append({"address": rc["address"], "actions": change.get("actions"),
                        "security_keys": touched})
    return out

if __name__ == "__main__":
    for row in risky("/tmp/tf.json"):
        print(row)
```

Each row is a planned change that touches a security property; `actions` containing `delete` is the higher-risk class and the report says so.
