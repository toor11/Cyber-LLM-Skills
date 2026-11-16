# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`gcp-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `gcloud` | `gcloud projects get-iam-policy P --flatten="bindings[].members"` | Grants with their members, flattened for filtering | Cloud SDK |
| `gcloud` | `gcloud asset search-all-iam-policies --scope=projects/P --query="policy:roles/owner"` | Every policy that grants a role, across the hierarchy | Cloud SDK |
| `gcloud` | `gcloud iam service-accounts keys list --iam-account SA` | Existing user-managed keys, the persistence inventory | Cloud SDK |
| `gcloud` | `gcloud resource-manager org-policies describe CONSTRAINT --organization ORG` | Whether a constraint is enforced and where | Cloud SDK |
| `forseti`/`gcp-iam-collector` | `python collector.py --project P --out iam.json` | Offline IAM graph for path analysis | assessment hosts |

## Minimal script shape

```python
# Rank service accounts by what an actAs hop would reach.
import json
import subprocess

ESCALATION = {"roles/owner", "roles/editor", "roles/iam.securityAdmin",
              "roles/resourcemanager.projectIamAdmin"}

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def sa_roles(project: str) -> dict[str, set[str]]:
    pol = json.loads(sh("gcloud", "projects", "get-iam-policy", project, "--format=json"))
    out: dict[str, set[str]] = {}
    for b in pol.get("bindings", []):
        for m in b.get("members", []):
            if m.startswith("serviceAccount:"):
                out.setdefault(m, set()).add(b["role"])
    return out

def act_as_targets(project: str, roles: dict[str, set[str]]) -> list[dict]:
    return [{"sa": sa, "roles": sorted(r & ESCALATION)}
            for sa, r in roles.items() if r & ESCALATION]

if __name__ == "__main__":
    for row in act_as_targets("my-project", sa_roles("my-project")):
        print(row)
```

Each row is a service account whose `actAs` hop reaches an escalation role; pair it with the policy that grants `serviceAccountUser` on that account to find the entry point.
