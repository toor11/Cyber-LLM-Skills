# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sarif-and-assessment-report-automation`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** SARIF 2.1.0; consumers expect `$schema`, `version`, `runs[].tool.driver.name`, and per-result `ruleId` plus `locations`.
- **Validation Gate:** `python -c "import json; json.load(open('out.sarif'))"` plus a schema validator in CI.
- Compute fingerprints from path, rule id, and a normalised code snippet; including line numbers makes them drift on every edit above the finding.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `codeql` | `codeql database analyze db rule.ql --format=sarif-latest --output=out.sarif` | Produce a SARIF document from a query run | Cross-platform |
| `semgrep` | `semgrep --config rules/ --sarif --output=out.sarif` | Produce SARIF from pattern rules | Cross-platform |
| `jq` | `jq ".runs[].results" out.sarif` | List results per run without a full parser, so each run can be counted | Linux, macOS, Windows |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import sys

path = sys.argv[1]
doc = json.load(open(path, encoding="utf-8"))
assert doc["version"] == "2.1.0", doc.get("version")
fps = set()
for run in doc["runs"]:
    for res in run.get("results", []):
        fp = res.get("partialFingerprints", {}).get("primaryLocationLineHash")
        if fp:
            fps.add(fp)
print(len(fps), "distinct findings")
```
