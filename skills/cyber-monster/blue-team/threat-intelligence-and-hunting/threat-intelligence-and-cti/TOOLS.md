# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-intelligence-and-cti`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mitreattack-python` | `python -c "from mitreattack.stix20 import MitreAttackData; d=MitreAttackData('enterprise-attack.json'); print(len(d.get_techniques(remove_revoked_deprecated=True)))"` | Query the local ATT&CK corpus for current technique ids | Cross-platform |
| `misp` | `curl -s -H "Authorization: $MISP_KEY" -H 'Accept: application/json' $MISP/attributes/restSearch` | Pull stored indicators with their context and timestamps | Cross-platform |
| `git` | `git log --since=90.days -- products/` | Show which products fed a decision in the last quarter | Cross-platform |
| `yaml`/`jinja` | render the product template from a YAML record | Keep the estimative structure consistent across analysts | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import datetime as dt, yaml

REQUIRED = ("pir", "consumer", "decision", "expires", "assessment", "confidence", "evidence")
for path in ["products/pir-2026-14.yml"]:
    p = yaml.safe_load(open(path))
    missing = [k for k in REQUIRED if not p.get(k)]
    if missing:
        print(path, "MISSING", missing)
        continue
    exp = dt.date.fromisoformat(str(p["expires"]))
    if p["confidence"] == "high" and len(p["evidence"]) < 2:
        print(path, "high confidence with fewer than two evidence items")
    print(path, "ok", "expires in", (exp - dt.date(2026, 11, 14)).days, "days")
```

## Verification

- A product with one evidence item and high confidence fails the check, which is the calibration rule.
- An expired PIR prints a negative day count, so retirement is visible rather than assumed.
- Template fields match the register, so a new product cannot omit the estimative statement.
