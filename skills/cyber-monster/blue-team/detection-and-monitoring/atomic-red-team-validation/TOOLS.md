# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`atomic-red-team-validation`](SKILL.md) | Family: **Detection and Monitoring**

Verified invocation shapes for the emulation framework and the sensors a validation depends on. Flag names below come from the current Invoke-AtomicRedTeam distribution; confirm with `Get-Help Invoke-AtomicTest -Full` on the installed module, because parameter sets change between releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Invoke-AtomicRedTeam` (PowerShell Gallery) | `Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser` | Install the execution framework without the atomics definitions | Windows, Linux, macOS |
| Installer script with atomics | `IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics` | Install framework plus the atomics folder; add `-NoPayloads` for YAML definitions only | Windows, Linux, macOS |
| `Invoke-AtomicTest` prereq gate | `Invoke-AtomicTest T1003.001 -TestNumbers 1 -CheckPrereqs` | Report whether the test can execute; an unmet prereq makes the run inconclusive | Windows, Linux, macOS |
| `Invoke-AtomicTest` execute | `Invoke-AtomicTest T1053.005 -TestNumbers 2 -TimeoutSeconds 120` | Run one bounded atomic; the timeout prevents an interactive session | Windows, Linux, macOS |
| `Invoke-AtomicTest` cleanup | `Invoke-AtomicTest T1053.005 -TestNumbers 2 -Cleanup` | Reverse the test's artifacts; verify afterwards with a targeted query | Windows, Linux, macOS |
| `Get-AtomicTechnique` | `Get-AtomicTechnique -TechniqueName T1053.005` | Dump the test's `prereqs`, executor, and `cleanup_command` before running it | Windows, Linux, macOS |
| Sysmon service control | `sysmon -c` then `sysmon64 -c` | Print the effective Sysmon configuration to prove which event IDs a host actually emits | Windows |
| Velociraptor client query | `velociraptor.exe query "SELECT * FROM info()"` | Confirm agent version and host identity from the collection side of the validation | Windows, Linux, macOS |

## Minimal Script Shape

The shape below refuses to record a pass when the artifact was never harvested, and it always runs cleanup.

```powershell
# Validate one rule against one atomic, with a harvest gate before the verdict.
param(
  [Parameter(Mandatory)] [string]$Technique = 'T1053.005',
  [Parameter(Mandatory)] [int]$TestNumber = 2,
  [Parameter(Mandatory)] [string]$RuleId = 'sched_task_creation'
)
$ErrorActionPreference = 'Stop'

# 1. Prereq gate: an unmet prerequisite means the run cannot validate anything.
$prereq = Invoke-AtomicTest $Technique -TestNumbers $TestNumber -CheckPrereqs 6>&1 | Out-String
if ($prereq -match 'Prerequisites not met') {
  throw "INCONCLUSIVE (Prerequisite Unmet) for $Technique test $TestNumber"
}

# 2. Bounded execution, bracketed by wall-clock timestamps for the harvest window.
$Start = (Get-Date).ToUniversalTime()
Invoke-AtomicTest $Technique -TestNumbers $TestNumber -TimeoutSeconds 120 | Out-String | Write-Verbose
$End = (Get-Date).ToUniversalTime()

# 3. Harvest placeholder: substitute your own index query and assert a non-zero count.
$Harvest = $Start.AddMinutes(-5).ToString('o') + ' .. ' + $End.AddMinutes(5).ToString('o')
Write-Host "HARVEST_WINDOW=$Harvest rule=$RuleId technique=$Technique test=$TestNumber"

# 4. Cleanup always runs, even on failure, and its result is printed for the record.
try {
  Invoke-AtomicTest $Technique -TestNumbers $TestNumber -Cleanup | Out-String | Write-Verbose
} finally {
  Get-ScheduledTask | Where-Object { $_.Date -gt $Start } |
    Select-Object TaskName, TaskPath, Date | Format-Table | Out-String | Write-Host
}
```

## Notes That Prevent Wrong Runs

- `-CheckPrereqs` exit text, not exit code, carries the verdict on several module versions; match the output string rather than relying on `$LASTEXITCODE`.
- `-TimeoutSeconds` bounds the atomic, not the harvest. Keep the harvest window open long enough for forwarder batching, and record the delay you allowed.
- `-NoPayloads` installs YAML definitions only. That is the right choice on a host where the payload binaries would be quarantined by the AV product under test.
- Cleanup is a command from the atomic's YAML, not a rollback guarantee. Verify the artifact is gone with a targeted query; do not trust the absence of an error message.
- Record the deployed rule version or commit hash beside the run. A rule edited mid-validation makes alert and artifact incomparable.
