# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`azure-and-entra-attacks-rbac-and-managed-identity`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `az` | `az role assignment list --all --include-inherited` | Every assignment with its scope, which is the review's primary input | Azure CLI |
| `az` | `az identity federated-credential list --identity-name I --resource-group R` | The external subjects that can assume the identity | Azure CLI |
| `kubectl` | `kubectl auth can-i patch serviceaccounts -n prod` | Whether the Kubernetes side allows the annotation change | kubectl |
| `az` | `az keyvault secret list --vault-name V` | The actual data exposure behind a Key Vault role | Azure CLI |
| `AzureHound` | `azurehound -c list -o out.json` | The graph for path analysis across assignments and identities | assessment hosts |

## Minimal script shape

```python
# Rank identity exposure by scope depth and role privilege.
import json
import subprocess

PRIVILEGED = {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def depth(scope: str) -> int:
    return scope.lower().rstrip("/").count("/")

def exposure() -> list[dict]:
    rows = json.loads(sh("az", "role", "assignment", "list", "--all", "--output", "json"))
    out = []
    for r in rows:
        scope = r.get("scope", "")
        role = r.get("roleDefinitionName", "")
        if role in PRIVILEGED or depth(scope) <= 2:
            out.append({"principal": r.get("principalName"), "role": role,
                        "scope": scope, "depth": depth(scope)})
    return sorted(out, key=lambda x: x["depth"])

if __name__ == "__main__":
    for row in exposure():
        print(row)
```

Rows at depth 1-2 (subscription or management group) with a privileged role are the top of the report; depth 6+ entries with `Key Vault Secrets User` are the controls to cite.
