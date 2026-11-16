# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ci-cd-and-dependency-attacks-pipeline-injection`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rg` | `rg -n -A4 "run:" .github/workflows/` | Interpolation inside shell blocks | any |
| `actionlint` | `actionlint -shellcheck= .github/workflows/*.yml` | Known injection patterns and expression misuse | Go binary |
| `zizmor` | `zizmor --format plain .github/workflows/` | Template-injection findings with line numbers | Python |
| `gh` | `gh run view --log` | Whether a lab reproduction executed, from the log itself | GitHub CLI |
| `gitlab-ci-lint` | `curl --data-urlencode "content@.gitlab-ci.yml" "$GITLAB/api/v4/ci/lint"` | Whether the pipeline parses as expected before you reason about it | any |

## Minimal script shape

```python
# Report every GitHub event field that reaches a run block, per workflow.
import pathlib
import re

EVENT = re.compile(r"\$\{\{\s*(github\.event\.[A-Za-z0-9_.\[\]']+)[^}]*\}\}")
CONTROLLED = ("pull_request", "issue", "comment", "commits", "head_ref", "discussion")

def findings(root: str) -> list[dict]:
    out = []
    for p in pathlib.Path(root).glob("*.yml"):
        in_run = False
        for i, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
            if re.match(r"\s*run:", line):
                in_run = True
            elif re.match(r"\s*[a-z_-]+:", line):
                in_run = False
            if not in_run:
                continue
            for field in EVENT.findall(line):
                if any(c in field for c in CONTROLLED):
                    out.append({"file": p.name, "line": i, "field": field})
    return out

if __name__ == "__main__":
    for f in findings(".github/workflows"):
        print(f)
```

Each entry is a contributor-controlled field reaching a shell; the remediation rewrites it as an `env:` key referenced with quotes.
