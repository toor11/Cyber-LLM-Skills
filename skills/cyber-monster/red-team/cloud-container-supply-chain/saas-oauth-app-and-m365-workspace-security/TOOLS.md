# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`saas-oauth-app-and-m365-workspace-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `az` | `az rest --url https://graph.microsoft.com/v1.0/oauth2PermissionGrants` | Delegated grants with consent type and scope | Azure CLI |
| `az` | `az rest --url .../servicePrincipals/ID/appRoleAssignments` | Application-role grants | Azure CLI |
| `ExchangeOnline` | `Get-InboxRule -Mailbox U` | Mailbox forwarding rules | Exchange PowerShell |
| `ExchangeOnline` | `Get-MailboxPermission -Identity U` | Delegates with full access | Exchange PowerShell |
| `jwt` | `jwt decode "$TOKEN" --json` | The scopes a token actually carries, from the token itself | jwt-cli |

## Minimal script shape

```python
# Rank grants by breadth and data sensitivity.
import json
import subprocess

SENSITIVE = ("Mail.Read", "Mail.Send", "Files.ReadWrite.All", "Sites.FullControl.All",
             "Directory.ReadWrite.All", "Chat.Read.All")

def graph(path: str) -> dict:
    out = subprocess.run(["az", "rest", "--method", "get", "--url",
                          f"https://graph.microsoft.com/v1.0{path}", "--output", "json"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)

def rank() -> list[dict]:
    rows = []
    for g in graph("/oauth2PermissionGrants")["value"]:
        scopes = [s for s in (g.get("scope") or "").split() if s in SENSITIVE]
        if scopes:
            rows.append({"client": g["clientId"], "consent": g["consentType"],
                         "sensitive": scopes,
                         "tenant_wide": g["consentType"] == "AllPrincipals"})
    return rows

if __name__ == "__main__":
    for row in rank():
        print(row)
```

`tenant_wide: True` with a sensitive scope is the top of the report; `consent: Principal` with one scope is the control to contrast it against.
