# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`azure-and-entra-attacks-token-and-consent-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `az` | `az rest --url https://graph.microsoft.com/v1.0/policies/authorizationPolicy` | The user-consent setting that enables or blocks the attack | Azure CLI |
| `az` | `az rest --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$filter=consentType eq 'AllPrincipals'"` | Tenant-wide grants | Azure CLI |
| `az` | `az rest --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=activityDisplayName eq 'Consent to application'"` | Who consented, to what, when | Azure CLI |
| `Microsoft.Graph` | `Get-MgServicePrincipal -Filter "appId eq '$APP'"` | Publisher verification and owning tenant for a client app | PowerShell 7 |
| `AADInternals` | `Get-AADIntAccessTokenForGraph` | Lab-only token handling for verifying scopes | PowerShell, isolated tenant |

## Minimal script shape

```python
# Classify every tenant-wide grant as internal, verified-external, or unverified.
import json
import subprocess

TENANT = "00000000-0000-0000-0000-000000000000"

def graph(path: str) -> dict:
    out = subprocess.run(["az", "rest", "--method", "get", "--url",
                          f"https://graph.microsoft.com/v1.0{path}", "--output", "json"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)

def classify() -> list[dict]:
    rows = []
    for g in graph("/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'")["value"]:
        sp = graph(f"/servicePrincipals/{g['clientId']}?$select=displayName,appOwnerOrganizationId,verifiedPublisher")
        owner = sp.get("appOwnerOrganizationId")
        rows.append({
            "client": sp.get("displayName"),
            "scope": g.get("scope"),
            "external": owner != TENANT,
            "verified": bool(sp.get("verifiedPublisher", {}).get("displayName")),
        })
    return rows

if __name__ == "__main__":
    for r in classify():
        if r["external"] and not r["verified"]:
            print("UNVERIFIED EXTERNAL GRANT", r)
```

Every printed row is a grant to an application the tenant does not own and Microsoft has not verified; the remediation is revoke plus disable the service principal.
