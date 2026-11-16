# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`azure-and-entra-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `az` | `az rest --method get --url https://graph.microsoft.com/v1.0/oauth2PermissionGrants` | Delegated grants including `AllPrincipals` | Azure CLI 2.47+ |
| `az` | `az rest --method get --url .../servicePrincipals/$ID/appRoleAssignments` | Application-role grants on one service principal | Azure CLI |
| `Microsoft.Graph` | `Get-MgOauth2PermissionGrant -All` | The same grants through the PowerShell SDK | PowerShell 7 |
| `az` | `az rest --url .../identity/conditionalAccess/policies` | Conditional Access policies and their session controls | Azure CLI |
| `AzureHound` | `azurehound -c list -o out.json` then `bloodhound` | The Entra graph for path analysis across roles and grants | assessment hosts |

## Minimal script shape

```python
# Rank delegated grants by breadth, from the Graph API.
import json
import subprocess

SENSITIVE = ("Mail.Read", "Mail.ReadWrite", "Files.Read.All", "Directory.ReadWrite.All",
             "Sites.Read.All", "Chat.Read.All")

def graph(path: str) -> dict:
    out = subprocess.run(["az", "rest", "--method", "get", "--url",
                          f"https://graph.microsoft.com/v1.0{path}", "--output", "json"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)

def risk() -> list[dict]:
    rows = []
    for g in graph("/oauth2PermissionGrants")["value"]:
        scopes = [s for s in (g.get("scope") or "").split() if s]
        broad = g.get("consentType") == "AllPrincipals"
        sensitive = [s for s in scopes if s in SENSITIVE]
        if broad and sensitive:
            rows.append({"client": g["clientId"], "scopes": sensitive,
                         "affected": "all users"})
    return rows

if __name__ == "__main__":
    for r in risk():
        print(r)
```

Every returned row is a tenant-wide consent to a sensitive scope; the report names the client and the scope, and the remediation is a per-principal grant or an access review.
