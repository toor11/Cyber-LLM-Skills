# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ruby-on-rails-security`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `brakeman` | `brakeman -q -f json -o brakeman.json --no-pager` | Mass assignment, SQL, and loader patterns with confidence levels | Ruby |
| `bundler-audit` | `bundle exec bundler-audit check --update` | Advisory match for gem versions | Ruby |
| `routes` | `bin/rails routes --expanded` | Full route and action inventory | Ruby |
| `rspec` | `bundle exec rspec spec/requests` | Encode the authorisation probe as a request spec | Ruby |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Evidence: route inventory, static findings, and gem advisories.
set -euo pipefail
bin/rails routes --expanded > routes.txt
brakeman -q -f json -o brakeman.json --no-pager || true
bundle exec bundler-audit check --update || true
python - <<'PY'
import json
try:
    d = json.load(open("brakeman.json"))
except FileNotFoundError:
    raise SystemExit("brakeman output missing")
for w in d.get("warnings", []):
    print(w["check_name"], w["confidence"], f"{w['file']}:{w['line']}")
PY
```

## Verification

- Every printed warning is dispositioned; high-confidence mass-assignment and SQL warnings are usually real.
- The route inventory includes member and collection routes, which is where custom actions appear.
- `bundler-audit` reports no unpatched gem advisories, or each is recorded with a reachability note.
