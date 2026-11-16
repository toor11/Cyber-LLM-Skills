# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`secure-code-review`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `semgrep` | `semgrep scan --config p/owasp-top-ten --config p/secrets --sarif --output semgrep.sarif .` | Entry-point and sink candidates with rule ids you can cite | Cross-platform |
| `codeql` | `codeql database create db --language=python --source-root .` then `codeql database analyze db python-security-extended.qls --format=sarif-latest --output=codeql.sarif` | Path-proven data flow, which is the witness path a review needs | Cross-platform |
| `git` | `git diff --stat origin/main...HEAD` and `git log -p -S 'render_template_string'` | Scope the review to the changed hunks and find history of the dangerous call | Cross-platform |
| `flask` / `django-admin` | `flask --app app routes` / `python manage.py show_urls` | Dump the routing table so entry-point enumeration is complete | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Review evidence: dump routes, then run path-proven analysis on the diff.
set -euo pipefail
cd "${1:?repo path}"
git diff --name-only origin/main...HEAD > changed.txt
codeql database create .codeql-db --language=python --source-root . --overwrite
codeql database analyze .codeql-db python-security-extended.qls \
  --format=sarif-latest --output codeql.sarif --sarif-add-file-contents
python - <<'PY'
import json
d = json.load(open("codeql.sarif"))
for run in d["runs"]:
    for res in run.get("results", []):
        loc = res["locations"][0]["physicalLocation"]
        print(loc["artifactLocation"]["uri"], loc["region"].get("startLine"), res["ruleId"])
PY
```

## Verification

- `codeql.sarif` parses as JSON and every printed path exists in `changed.txt` or is a direct callee of a changed file.
- Each printed rule id maps to a CWE you can name; discard rules whose CWE does not match the review question.
- Re-running on a clean tree produces zero results for the fixed commit, which is the regression signal you hand back.
