# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`codeql-query-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** CodeQL CLI 2.2x, modular dataflow API (`DataFlow::ConfigSig`, `TaintTracking::Global`), `@kind path-problem` for findings with flows.
- **Validation Gate:** `codeql query compile` then `codeql database analyze --format=sarif-latest` on both the vulnerable and fixed revisions.
- The legacy `class Config extends TaintTracking::Configuration` API is removed from current releases; new queries must use modules.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `codeql` | `codeql version` | Pin CLI version before quoting pack behaviour | Cross-platform |
| `codeql database create` | `codeql database create db --language=java --source-root ./src` | Build the database that queries run against | Cross-platform |
| `codeql query format` | `codeql query format MyQuery.ql --output=formatted.ql` | Normalise QL formatting so reviews diff semantics, not spacing | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import subprocess

subprocess.run(["codeql", "database", "analyze", "db", "MyQuery.ql",
                "--format=sarif-latest", "--output", "out.sarif"], check=True)
sarif = json.load(open("out.sarif", encoding="utf-8"))
results = sarif["runs"][0].get("results", [])
print(len(results))
for r in results[:10]:
    loc = r["locations"][0]["physicalLocation"]
    print(loc["artifactLocation"]["uri"], loc.get("region", {}).get("startLine"))
```
