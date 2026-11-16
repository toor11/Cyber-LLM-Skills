# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ci-cd-and-dependency-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `gh` | `gh api repos/O/R/actions/permissions/workflow` | The repository's default token permission | GitHub CLI |
| `rg` | `rg -n -e 'pull_request_target' -e 'uses: .*@v[0-9]' .github/workflows/` | The two highest-yield patterns in one pass | any |
| `actionlint` | `actionlint .github/workflows/*.yml` | Syntax and known-misconfiguration findings, including expression injection | Go binary |
| `zizmor` | `zizmor .github/workflows/` | Security findings for workflows, including template injection and unpinned actions | Python |
| `npm` | `npm ci --ignore-scripts --audit` | Installs without running dependency scripts and reports advisories | Node |

## Minimal script shape

```python
# Rank workflows by contributor-reachable authority.
import pathlib
import re

RISK = {
    "pr_target": re.compile(r"on:\s*pull_request_target"),
    "write_all": re.compile(r"permissions:\s*write-all"),
    "tag_pinned": re.compile(r"uses:\s*[^@\s]+@v[0-9]"),
    "secrets": re.compile(r"secrets\.[A-Z_]+"),
    "head_checkout": re.compile(r"head\.sha"),
}

def score(path: pathlib.Path) -> dict:
    text = path.read_text(errors="ignore")
    hits = [name for name, pat in RISK.items() if pat.search(text)]
    return {"workflow": path.name, "hits": hits,
            "contributor_reachable": "pr_target" in hits and "head_checkout" in hits}

if __name__ == "__main__":
    for p in pathlib.Path(".github/workflows").glob("*.yml"):
        row = score(p)
        if row["contributor_reachable"]:
            print("CONTRIBUTOR AUTHORITY", row)
```

A `contributor_reachable` workflow is the finding; the `hits` list tells you which of the five patterns made it so.
