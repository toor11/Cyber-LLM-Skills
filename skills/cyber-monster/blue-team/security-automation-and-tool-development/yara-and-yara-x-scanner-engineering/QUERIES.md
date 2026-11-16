# Detection Queries and Telemetry Artifacts

> Sub-skill: [`yara-and-yara-x-scanner-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Scan, compile, and profiling artifacts owned by this slug. Verify every flag against `yr --help` / `yr scan --help` on the installed YARA-X release before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `yr compile rules/` non-zero exit | High | A rule is illegal under YARA-X's stricter regex/atom rules; blocks the build before scanning |
| 2 | `yr scan --profiling` single-rule dominance | High | One rule's atoms are pathological; the slowdown is rule-shaped, not I/O-shaped |
| 3 | `--timeout` fired on a target | Medium | A crafted or very large file exceeded the budget; the scan result for that target is incomplete |
| 4 | Clean-ware fixture matched | High | The rule is a false-positive generator regardless of how many malicious samples it catches |
| 5 | `-C/--compiled-rules` artifact older than the source rule | High | The scan used stale rules; results describe a previous rule revision |

## Detection Artifacts

```text
[yara-and-yara-x-scanner-engineering:rule-spec] yr compile rules/ -> exit 0 required before any scan
[yara-and-yara-x-scanner-engineering:filter-fp] positive fixture matches AND clean-ware fixture does not
[yara-and-yara-x-scanner-engineering:correlate] rule identifier + namespace + offset identify one hit unambiguously
```

Compile gate, then a bounded scan emitting machine-readable output (Windows PowerShell 5.1):

```powershell
yr compile .\rules\ | Out-Host
$compileExit = $LASTEXITCODE
if ($compileExit -ne 0) { Write-Error "yr compile failed: $compileExit"; exit 2 }
yr scan --timeout 30 --max-matches-per-pattern 100 --output-format ndjson .\rules\ .\fixtures\positive\ |
    Set-Content .\build\hits-positive.ndjson
```

Profiling pass, used only when a scan is slower than its budget:

```powershell
yr scan --profiling --threads 4 .\rules\ .\corpus\cleanware\ | Out-File .\build\profile.txt
Select-String -Path .\build\profile.txt -Pattern 'total_time|slowest'
```

Python differential gate (positive must match, benign must not):

```python
import yara_x

compiler = yara_x.Compiler()
compiler.new_namespace("apt_fixture")
compiler.add_source(open("rules/apt_fixture.yar", encoding="utf-8").read())
rules = compiler.build()

scanner = yara_x.Scanner(rules)
scanner.set_timeout(30)
scanner.max_matches_per_pattern(100)
assert scanner.scan_file("fixtures/positive/sample.bin").matching_rules, "positive fixture did not match"
assert not scanner.scan_file("fixtures/cleanware/notepad.exe").matching_rules, "clean-ware false positive"
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Fail the rule PR when `yr compile` breaks, even if every existing rule still scans — a rule that cannot compile will silently disappear from a directory scan.
- Re-benchmark after any rule edit that changes a regular expression; atom extraction changes with it.
