# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`report-writing-and-findings`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a finding schema with title, location, invariant, baseline, probe, impact, rating rationale, remediation, and evidence.
- **Validation Gate:** one reproduction executed by someone other than the author before submission.
- Store evidence with timestamps and hashes; a screenshot without a date is weaker than a stored request and response.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D- -o body.json -H "Authorization: Bearer $A" https://api.client.example/v2/invoices/B` | Capture request and response for the evidence set | Cross-platform |
| `python` | `python -c "import yaml; print(sorted(yaml.safe_load(open('finding.yaml'))))"` | Confirm the finding carries every required field | Cross-platform |
| `git` | `git diff --unified=3` | Produce the minimal remediation diff | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import yaml

f = yaml.safe_load(open("finding.yaml", encoding="utf-8"))
required = ("title", "location", "invariant", "baseline", "probe", "impact", "remediation", "rating_rationale")
missing = [k for k in required if not f.get(k)]
print("complete" if not missing else f"missing: {missing}")
```
