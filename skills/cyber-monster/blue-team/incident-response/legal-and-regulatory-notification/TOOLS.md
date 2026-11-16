# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`legal-and-regulatory-notification`](SKILL.md) | Family: **Incident Response**

Verified evidence-assembly tooling. Everything here collects and hashes records so the awareness timeline can be reproduced identically for counsel, insurer and regulator. Nothing here sends a notification, drafts a statement or contacts a regulator.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-WinEvent` | `Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=<t>; EndTime=<t>} -MaxEvents 5000` | Export the security-record slice that brackets the awareness window | Windows |
| `wevtutil` | `wevtutil epl Security C:\case\Security.evtx` | Lossless channel export for counsel-facing evidence | Windows |
| `curl` | `curl -sS -u <user>:<token> "https://<siem>/services/search/jobs/export" -d search="<query>" -d output_mode=json` | Deterministic SIEM export with a query recorded beside the output | Cross-platform |
| `Get-FileHash` | `Get-FileHash -Algorithm SHA256 -Path <dir>\*` | Integrity manifest for the evidence package | Windows |
| `git log` | `git log --since=<t> --until=<t> --format="%H %aI %an %s"` | Change history for configuration or infrastructure-as-code evidence | Cross-platform |
| `pdftotext` | `pdftotext -layout contract.pdf contract.txt` | Extract contract clause text for human reading; no interpretation | Cross-platform |

## Minimal Script Shape

The shape below assembles a reproducible awareness-timeline package. It refuses to emit a package when any of the five awareness moments lacks a source identifier, because an incomplete timeline is worse than none — it invites a deadline to be calculated from a guess.

```powershell
# awareness-package.ps1 — assemble, hash and seal. Sends nothing.
[CmdletBinding()] param(
    [Parameter(Mandatory)][string]$CaseId,
    [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# The five moments. Blank values are a blocking condition, not a blank field.
$moments = [ordered]@{
    'T0_alert_fired'        = Read-Host "Alert fired (UTC ISO8601) + source ID"
    'T1_ticket_created'     = Read-Host "Ticket created (UTC ISO8601) + ticket ID"
    'T2_human_acknowledged' = Read-Host "Human acknowledgement (UTC ISO8601) + record"
    'T3_escalated'          = Read-Host "Escalation to decision-maker (UTC ISO8601) + record"
    'T4_counsel_engaged'    = Read-Host "Counsel engaged (UTC ISO8601) + record"
}

$missing = $moments.GetEnumerator() | Where-Object { [string]::IsNullOrWhiteSpace($_.Value) }
if ($missing) {
    Write-Warning "Blocking: $($missing.Count) awareness moment(s) have no source record."
    Write-Output "Do not assert a statutory start time until each moment has an artifact."
    exit 2
}

# Persist the timeline exactly as recorded, then hash it.
$timeline = $moments.GetEnumerator() | ForEach-Object {
    [pscustomobject]@{ Case=$CaseId; Moment=$_.Key; Record=$_.Value; CapturedUtc=(Get-Date).ToUniversalTime() }
}
$timeline | Export-Csv -NoTypeInformation "$OutDir\awareness-timeline.csv"

# Export the two channels most likely to be requested, and seal the package.
wevtutil epl Security "$OutDir\Security.evtx" 2>$null
Get-ChildItem $OutDir -File | Get-FileHash -Algorithm SHA256 |
    Select-Object Hash, Path | Export-Csv -NoTypeInformation "$OutDir\MANIFEST-sha256.csv"

Write-Output "Package assembled. Hand to counsel. Do not edit; re-export and re-hash instead."
```

## Notes That Prevent Wrong Runs

- `wevtutil epl` writes a lossless copy. Never use `wevtutil cl` to "clean up" a channel after export — clearing destroys the artifact whose absence will be questioned.
- SIEM export output is only evidence if the query that produced it is recorded beside it. Store the exact search string with the output, or the export cannot be reproduced.
- A hash manifest proves the package has not changed since sealing. It does not prove the underlying events are complete; state the channels and windows collected, and the ones that were unavailable.
- `pdftotext` extraction is for human reading. Never let automated extraction of a deadline into a tracker substitute for a human-confirmed clause reference.
- Clock discipline: every timestamp in the package must be UTC with the source's own offset recorded. A package mixing local and UTC times will be challenged, and the challenge will succeed.
