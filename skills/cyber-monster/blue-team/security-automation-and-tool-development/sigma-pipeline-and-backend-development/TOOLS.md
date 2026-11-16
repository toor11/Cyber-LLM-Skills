# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sigma-pipeline-and-backend-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `--help` on the installed version if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `pySigma` >= 1.5 (`sigma.collection.SigmaCollection`, `sigma.processing.pipeline.ProcessingPipeline`, `sigma.processing.pipeline.ProcessingItem`, `sigma.processing.pipeline.ProcessingPipelineResolver`, `sigma.correlations.SigmaCorrelationRule`) plus `sigma-cli`
- **Validation Gate:** `python -m py_compile sigma_pipeline_check.py; sigma check rules/`
- **Never:** archived `sigmac` (no object model, no structured per-rule errors)

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sigma-cli` | `sigma list targets` / `sigma list pipelines` | Enumerate installed backend and pipeline identifiers before converting | Cross-platform |
| `sigma-cli` | `sigma plugin install splunk` | Install a backend in the same environment as `sigma-cli` (or `pipx inject sigma-cli <pkg>`) | Cross-platform |
| `sigma-cli` | `sigma check rules/` | Lint rule schema, modifiers, and logsource legality; non-zero on findings | Cross-platform |
| `sigma-cli` | `sigma convert -t splunk -p sysmon rules/` | Compile to the target query language with a named pipeline | Cross-platform |
| `sigma-cli` | `sigma list formats` | Show output formats accepted by `-f` for the selected backend | Cross-platform |
| `pySigma` | `ProcessingPipeline(name=..., priority=..., items=[...])` | Declare field/logsource transformations with an explicit ordering weight | Cross-platform |
| `pySigma` | `ProcessingPipelineResolver.resolve([p1, p2])` | Chain pipelines by `priority` instead of concatenation order | Cross-platform |
| `pySigma` | `SigmaCollection.load_ruleset([dir], collect_errors=True)` | Load then inspect `collection.errors` per file | Cross-platform |

## Minimal Script

```powershell
python -m pip install --upgrade "pysigma>=1.5" sigma-cli
sigma plugin install splunk
sigma list targets
sigma check .\rules\
sigma convert -t splunk -p sysmon .\rules\ | Set-Content .\build\rules.spl
python -m py_compile .\harness\sigma_pipeline_check.py
```

Exit-code contract for the wrapper: `0` all rules compiled and goldens matched, `1` rule or conversion finding, `2` missing plugin, unreadable path, or absent backend.
