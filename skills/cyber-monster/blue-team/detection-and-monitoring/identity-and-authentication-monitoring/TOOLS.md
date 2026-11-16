# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`identity-and-authentication-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Read-only access to the three identity event families. None of these commands revokes a session or changes a credential; those are approved containment actions performed after evidence capture. Verify flags against the installed module versions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Microsoft Graph PowerShell | `Get-MgAuditLogSignIn -Filter "createdDateTime ge 2026-11-13T00:00:00Z" -Top 200` | Interactive sign-in records with result codes, address, device, and conditional-access status | Windows PowerShell |
| Microsoft Graph PowerShell | `Get-MgAuditLogSignIn` filtered to non-interactive records, or the beta endpoint's non-interactive collection | Token-refresh evidence, the family most estates fail to onboard | Windows PowerShell |
| Microsoft Graph PowerShell | `Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge 2026-11-13T00:00:00Z" -Top 200` | Directory changes: role assignment, consent grant, credential addition | Windows PowerShell |
| `az rest` | `az rest --method get --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=50"` | Query the same data without the PowerShell module, useful in a pipeline | Cross-platform |
| `jq` | `jq -r` with an array filter emitting `createdDateTime`, `userPrincipalName`, `ipAddress`, and `status.errorCode` as tab-separated columns | Normalise Graph JSON into a tabular fixture for analysis or replay | Cross-platform |
| Microsoft Sentinel | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs` tables via KQL | Long-window correlation across all three families in one workspace | Azure |
| `Get-MgUserAuthenticationMethod` | `Get-MgUserAuthenticationMethod -UserId <upn>` | Enumerate an account's registered factors to detect an attacker-added method | Windows PowerShell |

## Minimal Script Shape

The script classifies one account's window into spray, fatigue, replay, or clean, and refuses to classify when the non-interactive stream is absent.

```bash
#!/usr/bin/env bash
# identity-classify.sh — classify one account's sign-in window from exported JSON.
set -euo pipefail

INTERACTIVE="${INTERACTIVE:?set INTERACTIVE to an exported interactive sign-in JSON}"
NONINTERACTIVE="${NONINTERACTIVE:?set NONINTERACTIVE to an exported non-interactive JSON}"

python3 - "$INTERACTIVE" "$NONINTERACTIVE" <<'PY'
import collections, json, sys

def load(path):
    data = json.load(open(path))
    return data.get("value", data if isinstance(data, list) else [])

inter = load(sys.argv[1])
nonint = load(sys.argv[2])

if not nonint:
    print("INCONCLUSIVE (Non-Interactive Stream Empty): token replay cannot be assessed")
    print("  onboard the non-interactive sign-in stream before classifying this account")

reasons = collections.Counter()
fails_by_ip = collections.Counter()
success_new_ip = []
for r in inter:
    code = str(r.get("status", {}).get("errorCode", ""))
    ip = r.get("ipAddress", "")
    if code == "0":
        success_new_ip.append((r.get("createdDateTime"), ip, r.get("appDisplayName")))
    else:
        reasons[code] += 1
        fails_by_ip[ip] += 1

print("failure_reasons:", dict(reasons.most_common(5)))
print("top_failing_ips:", fails_by_ip.most_common(5))
print(f"interactive_successes: {len(success_new_ip)}")
print(f"non_interactive_events: {len(nonint)}")

if fails_by_ip and success_new_ip:
    worst_ip, count = fails_by_ip.most_common(1)[0]
    if count >= 10 and any(ip == worst_ip for _, ip, _ in success_new_ip):
        print("CLASS: spray-success — failures then a success from the same address")
    else:
        print("CLASS: unresolved — failures and successes on different addresses")
else:
    print("CLASS: no failure-then-success pattern in this window")
print("NOTE: token replay is decided by a non-interactive success from an address")
print("      absent from the account's own 30-day baseline, not by this script.")
PY
```

## Notes That Prevent Wrong Runs

- In the Graph JSON, the error code is a string in some responses and a number in others; normalise before comparing or the failure counts silently zero out.
- Non-interactive records are grouped by the provider: many identical token refreshes collapse into few rows, so a count of non-interactive rows is not a count of user actions.
- A conditional-access block appears as a non-zero result code and is a control working, not an intrusion; always read the conditional-access field alongside the result.
- Geo-location fields are provider inferences; when a location decides the case, record the ASN as well and state which source supplied it.
- Never use a real user's credentials to verify a finding, and never reset a break-glass account as part of containment without a documented emergency approval.
