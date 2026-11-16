# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`secure-code-review-access-control-review`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `brakeman` | `brakeman -q --no-pager -f json -o brakeman.json` | Rails authorisation and mass-assignment candidates | Ruby |
| `semgrep` | `semgrep scan --config p/ruby --config p/python --config p/javascript --error` | Framework-agnostic lookup and permission patterns | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN_B" https://staging/invoices/$A_ID` | Substitution probe with a single observable | Cross-platform |
| `pytest`/`rspec` | `pytest -q tests/authz` and `bundle exec rspec spec/policies` | Encode the probe as a regression test at both layers | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import httpx

BASE = "https://staging"
def status(token, path):
    return httpx.get(f"{BASE}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=10).status_code

cases = [
    ("owner reads own",        TOKEN_A, f"/invoices/{A_ID}", 200),
    ("same role, other user",  TOKEN_B, f"/invoices/{A_ID}", 404),
    ("missing id",             TOKEN_B, "/invoices/00000000-0000-0000-0000-000000000000", 404),
    ("custom action, non-owner", TOKEN_B, f"/invoices/{A_ID}/approve", 404),
]
bad = [(n, s, e) for n, t, p, e in cases for s in [status(t, p)] if s != e]
print("failures:", bad)
raise SystemExit(0 if not bad else 1)
```

## Verification

- The owner case returns 200, proving the probe is not simply blocked by a broken token.
- Foreign and missing ids return the identical code, which is both the authorisation and the enumeration check.
- The custom-action case is included, because that is where this defect actually lives.
