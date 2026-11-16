# Detection Queries and Telemetry Artifacts

> Sub-skill: [`phishing-email-and-header-triage-automation`](SKILL.md) | Family: **Security Automation and Tool Development**

Header-boundary and artefact-extraction artifacts owned by this slug. Replace the expected `authserv-id` with your own receiving MTA identity before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `Authentication-Results` positioned above the first `Received` | High | The field was written by your receiving host, not the sender |
| 2 | `authserv-id` equal to the expected MTA identity | High | The result belongs to your infrastructure even if ordering is unusual |
| 3 | `Received` hop count and deltas with a large trailing gap | Medium | Delayed or replayed delivery, or a queueing hop |
| 4 | Deffanged URL in the report | High | Triage did not create a live link or fetch it |
| 5 | Attachment SHA-256 computed locally | High | The file is identified without execution or submission |

## Detection Artifacts

```text
[phishing-email-and-header-triage-automation:rule-spec] trust Authentication-Results only above your own Received and only with a matching authserv-id
[phishing-email-and-header-triage-automation:filter-fp] a sender-supplied auth header below the boundary is attacker-controlled, not evidence
[phishing-email-and-header-triage-automation:correlate] subject + From + attachment sha256 clusters a campaign across recipients
```

Header trust boundary, printed so the ordering decision is reviewable (Windows PowerShell 5.1 invoking Python):

```python
msg = email.message_from_bytes(raw, policy=email.policy.default)
for i, (name, value) in enumerate(msg.raw_items()):
    if name.lower() in ("received", "authentication-results", "arc-authentication-results", "dkim-signature"):
        print(i, name, value[:110].replace("\n", " "))
```

Defanging check on extracted URLs, which must produce no live scheme:

```powershell
$report = Get-Content .\build\verdict.json -Raw
if ($report -match '"https?://') { Write-Output "live URL in report"; exit 1 }
Select-String -Path .\build\verdict.json -Pattern 'hxxps?://|\[\.\]' | Measure-Object | Select-Object -ExpandProperty Count
```

Attachment hashing without opening the file:

```powershell
Get-ChildItem C:\evidence\phish\attachments\* |
    ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash)  $($_.Name)  $($_.Length)" }
```

Lookalike scoring inputs: the decoded ASCII form is what edit distance should be computed against.

```python
import idna

for label in ["xn--exmple-cua.com", "example.com", "examp1e.com"]:
    try:
        print(label, "->", idna.decode(label))
    except idna.IDNAError as exc:
        print(label, "invalid:", exc)
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Keep triage offline: no URL fetch, no image load, no attachment execution.
- Store the raw message with its hash so the verdict is reproducible after the mailbox changes.
