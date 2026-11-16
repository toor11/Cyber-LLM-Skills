# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`django-security-patterns`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `manage.py` | `python manage.py check --deploy --fail-level WARNING` | Settings and deployment checks Django itself knows about | Cross-platform |
| `show_urls` | `python manage.py show_urls --format=json` | Full route and action inventory including DRF routers | Cross-platform |
| `bandit` | `bandit -r . -f json -o bandit.json` | `mark_safe`, `RawSQL`, and unsafe-loader candidates | Python |
| `semgrep` | `semgrep scan --config p/django --config p/python --error` | DRF and template sink patterns | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Django review evidence: deploy checks, route inventory, then targeted greps.
set -euo pipefail
python manage.py check --deploy --fail-level WARNING
python manage.py show_urls --format=json > routes.json
python - <<'PY'
import json, pathlib, re
routes = json.load(open("routes.json"))
print("routes:", len(routes))
danger = re.compile(r"RawSQL\(|\.extra\(|mark_safe\(|objects\.get\(pk=")
for p in pathlib.Path(".").rglob("*.py"):
    if "migrations" in p.parts:
        continue
    for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        if danger.search(line):
            print(f"{p}:{i}: {line.strip()[:100]}")
PY
```

## Verification

- `check --deploy` exits zero; each warning it raises maps to a settings switch a reviewer must see.
- The route count matches the router configuration, so custom actions are present in the inventory.
- Every grep hit is dispositioned with the safe form or the reachability argument.
