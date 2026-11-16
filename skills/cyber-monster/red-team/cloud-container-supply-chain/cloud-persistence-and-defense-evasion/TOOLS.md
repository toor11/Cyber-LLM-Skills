# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`cloud-persistence-and-defense-evasion`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws iam list-access-keys --user-name U` | Credential inventory with creation dates | AWS CLI v2 |
| `aws` | `aws cloudtrail get-trail-status --name T` | Whether logging is on and delivering | AWS CLI v2 |
| `aws` | `aws events list-rules` | Scheduled invocations, the compute persistence surface | AWS CLI v2 |
| `az` | `az ad app credential list --id APP` | Application secrets and certificates with their validity | Azure CLI |
| `az` | `az rest --url .../identity/conditionalAccess/policies` | Policy state that could have been weakened | Azure CLI |
| `gcloud` | `gcloud iam service-accounts keys list --iam-account SA` | User-managed keys, the GCP credential persistence | Cloud SDK |

## Minimal script shape

```python
# Report persistent objects that no inventory baseline accounts for.
import json
import subprocess

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def access_keys() -> list[dict]:
    users = sh("aws", "iam", "list-users", "--query", "Users[].UserName", "--output", "text").split()
    out = []
    for u in users:
        data = json.loads(sh("aws", "iam", "list-access-keys", "--user-name", u,
                             "--query", "AccessKeyMetadata", "--output", "json"))
        for k in data:
            out.append({"user": u, "key": k["AccessKeyId"], "created": k["CreateDate"]})
    return out

def unexplained(keys: list[dict], known: set[str]) -> list[dict]:
    return [k for k in keys if k["key"] not in known]

if __name__ == "__main__":
    baseline = set(line.strip() for line in open("known_keys.txt"))
    for k in unexplained(access_keys(), baseline):
        print("UNEXPLAINED KEY", k)
```

Each printed key is a persistence candidate; the report pairs it with the CloudTrail `CreateAccessKey` event that names the creating principal.
