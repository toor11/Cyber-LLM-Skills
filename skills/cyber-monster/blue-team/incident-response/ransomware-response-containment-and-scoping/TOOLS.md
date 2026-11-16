# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ransomware-response-containment-and-scoping`](SKILL.md) | Family: **Incident Response**

Verified read-only enumeration for scoping. Nothing here isolates, disables, resets or deletes; isolation decisions are made after these results are recorded. Confirm flags with `<tool> --help` on the installed version.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-SmbShare` / `Get-SmbOpenFile` | `Get-SmbShare`, `Get-SmbOpenFile`, `Get-SmbSession` | Which shares exist and who holds an open handle right now, before you break one | Windows |
| `openfiles` | `openfiles /query /fo csv` | Legacy share handle enumeration on hosts without the SMB cmdlets | Windows Server |
| `net view` / `net session` | `net view \\<host>` · `net session` | Session enumeration from the host's own perspective | Windows |
| `Get-WinEvent` (5145) | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145; StartTime=(Get-Date).AddHours(-6)}` | Detailed file-share access, the core scope artifact for share spread | Windows Server |
| `Velociraptor` (`Windows.Triage.Targets`) | `velociraptor artifacts collect Windows.Triage.Targets --args Target=EventLogs` | Pre-isolation triage collection; artifact renamed from `Windows.KapeFiles.Targets` in 0.75+ | Windows |
| `Get-MpComputerStatus` | `Get-MpComputerStatus`, `Get-MpPreference` | Read-only confirmation of whether endpoint protection is still active and what it excludes | Windows |

## Minimal Script Shape

The shape below builds the scope list and refuses to declare a host contained when its collection is missing or its writes continued. It changes nothing and is safe to run against production.

```powershell
# scope-report.ps1 — read-only scope and containment attestation.
[CmdletBinding()] param(
    [Parameter(Mandatory)][string]$HostsFile,
    [Parameter(Mandatory)][datetime]$IsolationUtc,
    [string]$OutDir = ".\scope"
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$rows = foreach ($h in Get-Content $HostsFile) {
    $h = $h.Trim(); if (-not $h) { continue }

    $shares = try { Get-SmbShare -CimSession $h -ErrorAction Stop | Select-Object -Expand Name } catch { $null }
    $sessions = try { (Get-SmbSession -CimSession $h -ErrorAction Stop).Count } catch { $null }
    $open = try { (Get-SmbOpenFile -CimSession $h -ErrorAction Stop).Count } catch { $null }

    # Coverage gate: absence of the audit log is a gap, never a clean host.
    $access = try {
        Get-WinEvent -CimSession $h -FilterHashtable @{LogName='Security'; Id=5145;
            StartTime=$IsolationUtc.AddHours(-6); EndTime=$IsolationUtc} -ErrorAction Stop
    } catch { $null }
    $post = try {
        Get-WinEvent -CimSession $h -FilterHashtable @{LogName='Security'; Id=5145;
            StartTime=$IsolationUtc} -ErrorAction Stop
    } catch { $null }

    [pscustomobject]@{
        Host              = $h
        Reachable         = [bool]$shares
        ShareCount        = ($shares | Measure-Object).Count
        ActiveSessions    = $sessions
        OpenHandles       = $open
        AccessEvents      = ($access | Measure-Object).Count
        PostIsolationWrites = ($post | Measure-Object).Count
        ScopeVerdict      = if (-not $shares) { 'UNMEASURED - unreachable' }
                            elseif ($null -eq $access) { 'UNMEASURED - no 5145 audit' }
                            elseif ($post) { 'NOT CONTAINED - writes after boundary' }
                            else { 'CONTAINED - no writes after boundary' }
    }
}
$rows | Export-Csv -NoTypeInformation "$OutDir\scope-report.csv"
$rows | Format-Table -AutoSize
if ($rows.ScopeVerdict -contains 'NOT CONTAINED - writes after boundary') {
    Write-Warning "At least one host still records share writes after the isolation timestamp."
    exit 2
}
```

## Notes That Prevent Wrong Runs

- `Get-SmbSession` and `Get-SmbOpenFile` break nothing, but the corresponding `Close-SmbSession` does. Never pipe enumeration output into a close operation without naming each session and recording why.
- Event ID 5145 requires the "Audit File Share" subcategory to be enabled with Success. If the log is empty, the correct verdict is unmeasured, not clean.
- `Get-WinEvent -CimSession` needs WinRM on the target. If WinRM was disabled by the operator, that refusal is itself a scope finding and must be recorded rather than retried silently.
- The triage artifact name changed between Velociraptor releases. Pin the version in the runbook or the collection silently gathers nothing.
- Never isolate the only route to the backup console, the hypervisor or the identity provider. Validate the out-of-band path with an actual login before the boundary change.
