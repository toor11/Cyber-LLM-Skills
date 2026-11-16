# Detection Queries and Telemetry Artifacts

> Sub-skill: [`sigma-pipeline-and-backend-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Compilation and CI artifacts owned by this slug: pipeline definitions, harness invocations, and the fixture shapes that prove a compiled query still matches. Verify backend and pipeline identifiers against `sigma list targets` / `sigma list pipelines` on the installed version before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `sigma check rules/` non-zero exit | High | A rule or modifier is illegal for the installed spec; stops the build before deployment |
| 2 | `collection.errors` non-empty after `load_ruleset(collect_errors=True)` | High | The rule tree does not parse; per-file attribution instead of a bare YAML traceback |
| 3 | Compiled query text differs from the committed golden file | High | Rule content or pipeline behaviour changed in this commit; reviewable drift |
| 4 | Positive fixture stops matching while its benign twin matches | Medium | Pipeline field mapping broke, not the detection logic |
| 5 | `sigma list targets` missing the expected backend identifier | High | Plugin never installed; `sigma convert -t` will fail for environmental reasons, not rule reasons |

## Detection Artifacts

```text
[sigma-pipeline-and-backend-development:rule-spec] sigma check rules/ -> exit 0 required before convert
[sigma-pipeline-and-backend-development:filter-fp] duplicate backend mapping (backend ECS pipeline + custom rename) yields process.process.command_line
[sigma-pipeline-and-backend-development:correlate] SigmaCorrelationRule requires name or id reference to an existing base rule
```

Compilation and fixture gate, run from the repository root in Windows PowerShell 5.1:

```powershell
python -m py_compile .\harness\sigma_pipeline_check.py
sigma check .\rules\ 2>&1 | Tee-Object -FilePath .\build\sigma-check.log
if ($LASTEXITCODE) { Get-Content .\build\sigma-check.log; exit 1 }
sigma convert -t splunk -p sysmon -f splunk .\rules\ | Set-Content .\build\rules.spl
Select-String -Path .\build\rules.spl -Pattern 'index=' -Quiet | Out-Null
```

Golden-file gate: compile each rule twice, once before and once after the change, and compare with `Compare-Object` so the diff names the rule that moved.

```powershell
Compare-Object (Get-Content .\baseline\rules.spl) (Get-Content .\build\rules.spl) |
  Select-Object SideIndicator, InputObject
```

Fixture differential: replay retained EVTX/JSON through the compiled query, asserting one hit for the malicious sample and zero for the benign twin.

```json
{"fixture": "encoded_powershell_positive", "expect_hits": 1, "event": {"EventID": 4688, "CommandLine": "powershell.exe -NoP -enc SQBFAFgA"}}
{"fixture": "encoded_powershell_benign", "expect_hits": 0, "event": {"EventID": 4688, "CommandLine": "powershell.exe -NoProfile -Command Get-Date"}}
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Block the merge when a compiled query changes without a matching rule or pipeline change in the same commit.
- Pin `pySigma` and the backend plugin versions in the pipeline lockfile; a plugin bump changes emitted query text by design.
