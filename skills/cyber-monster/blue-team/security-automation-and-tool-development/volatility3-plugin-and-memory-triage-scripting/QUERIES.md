# Detection Queries and Telemetry Artifacts

> Sub-skill: [`volatility3-plugin-and-memory-triage-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Plugin invocation and cross-view triage artifacts owned by this slug. Confirm plugin names against `vol -h` on the installed Volatility 3 release before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Non-zero row count from `windows.pslist` | High | Symbols resolved and the translation layer is valid; zero rows is a symbol problem first |
| 2 | PID present in `windows.psscan` but absent from `windows.pslist` | High | A process was unlinked from the active list; the discrepancy is the finding |
| 3 | `windows.malfind` region with no module backing | Medium | Executable private memory, requiring corroboration with `vadinfo` and parentage |
| 4 | `PluginRequirementException` at startup | High | A declared dependency version is unsatisfied; the framework is refusing rather than guessing |
| 5 | Consistent per-plugin row counts across two runs on the same image | High | The triage is reproducible against the recorded hash |

## Detection Artifacts

```text
[volatility3-plugin-and-memory-triage-scripting:rule-spec] every plugin run must report a row count; zero is a symbol question first
[volatility3-plugin-and-memory-triage-scripting:filter-fp] RWX regions from JIT engines are expected; require module-backing analysis
[volatility3-plugin-and-memory-triage-scripting:correlate] PID + create time joins pslist, psscan, and malfind views
```

Baseline triage run with explicit row counts (Windows PowerShell 5.1):

```powershell
$image = "C:\evidence\memory\workstation.raw"
$out = "C:\work\vol3"
New-Item -ItemType Directory -Force -Path $out | Out-Null

foreach ($plugin in @("windows.info", "windows.pslist", "windows.psscan", "windows.malfind")) {
    vol -f $image --output-dir $out $plugin | Out-Null
    $rows = (Get-ChildItem $out -Filter "*$($plugin.Split('.')[-1])*.json" -ErrorAction SilentlyContinue).Count
    Write-Output "$plugin artifacts=$rows"
}
```

Cross-view differential: PIDs in `psscan` but not `pslist`.

```powershell
$list = vol -f C:\evidence\memory\workstation.raw -r json windows.pslist | ConvertFrom-Json
$scan = vol -f C:\evidence\memory\workstation.raw -r json windows.psscan | ConvertFrom-Json
$hidden = $scan | Where-Object { $_.PID -notin $list.PID } | Select-Object PID, ImageFileName
$hidden | Format-Table -AutoSize
```

Module-backed analysis of a suspicious region before calling it injected:

```powershell
vol -f C:\evidence\memory\workstation.raw windows.vadinfo --pid 4412 | Select-String -Pattern 'Protection|File'
```

Hash and record the image so the run is reproducible:

```powershell
Get-FileHash C:\evidence\memory\workstation.raw -Algorithm SHA256 | Select-Object Hash, Path
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the image hash and the Volatility version with every triage report; a finding without both is not reproducible.
- Treat an all-zero result set as a failed run, not as a clean image.
