# Detection Queries and Telemetry Artifacts

> Sub-skill: [`edr-api-triage-and-containment-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Triage and guarded-response artifacts owned by this slug. Confirm endpoint paths, permission names, and rate limits against the vendor's current API documentation before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `--dry-run` plan naming a resolved machine id | High | The intended target was confirmed before any write call |
| 2 | `isIsolated` true on a read before the action | High | The host is already contained; re-isolation is a no-op |
| 3 | Protected tag or DC-style hostname on the target | High | The refusal path applies; a human decision is required |
| 4 | `IsolationType` recorded with the request | High | Scope of containment was an explicit choice |
| 5 | Audit line for every outcome including refusals and dry runs | High | The response action is attributable and reviewable |

## Detection Artifacts

```text
[edr-api-triage-and-containment-scripting:rule-spec] resolve hostname -> check protected -> check already-contained -> approval -> act -> confirm by read
[edr-api-triage-and-containment-scripting:filter-fp] 429 is backpressure, never "host not found"
[edr-api-triage-and-containment-scripting:correlate] machine id + audit request id ties the CLI action to the vendor action log
```

Dry-run first, always (Windows PowerShell 5.1):

```powershell
$env:MDE_TOKEN = (Get-Content Env:\MDE_TOKEN)
python .\edr_triage.py --hostname web01.example.internal --action isolate
$plan = $LASTEXITCODE
if ($plan -ne 0) { Write-Output "plan/refusal exit=$plan"; exit $plan }
```

Read-only inventory of isolation state for a batch of hosts, with backoff handled by the client:

```powershell
$hosts = Get-Content .\targets.txt
foreach ($h in $hosts) {
    python .\edr_triage.py --hostname $h --action report 2>&1 |
        Select-String -Pattern '"result"'
}
```

Confirming the action took effect rather than trusting the submission status:

```powershell
python .\edr_triage.py --hostname web01.example.internal --action report 2>&1 |
    Select-String -Pattern 'already_isolated'
```

FalconPy equivalent for CrowdStrike environments — host lookup and RTR session in separate classes:

```python
from falconpy import Hosts, RealTimeResponse

hosts = Hosts(client_id="<id>", client_secret="<secret>")
found = hosts.query_devices_by_filter(filter=f"hostname:'web01'")
device_ids = found["body"]["resources"]

rtr = RealTimeResponse(client_id="<id>", client_secret="<secret>")
session = rtr.init_session(device_id=device_ids[0])
print(session["body"]["resources"][0]["session_id"])
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Keep the protected-asset list in configuration under change control and review changes like firewall rules.
- Retain the audit log for the full incident lifetime; it is the record of who authorised each state change.
