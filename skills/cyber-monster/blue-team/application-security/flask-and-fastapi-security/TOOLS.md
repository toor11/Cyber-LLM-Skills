# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`flask-and-fastapi-security`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `flask` | `flask --app app routes` | Route inventory including blueprints | Cross-platform |
| `pip-audit` | `pip-audit -r requirements.txt --format json` | Advisory match for framework and parser versions | Cross-platform |
| `semgrep` | `semgrep scan --config p/flask --config p/python --error` | Template-source, mass-assignment, and SQL patterns | Cross-platform |
| `pytest` + `httpx` | `pytest -q tests/test_authz.py` | Encode the two-account probe as a regression test | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import httpx

BASE = "https://staging"
def call(token, method, path, **kw):
    return httpx.request(method, f"{BASE}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=10, **kw)

cases = [
    ("owner read",        call(TOKEN_A, "GET", f"/api/invoices/{A_ID}").status_code, 200),
    ("foreign read",      call(TOKEN_B, "GET", f"/api/invoices/{A_ID}").status_code, 404),
    ("missing read",      call(TOKEN_B, "GET", "/api/invoices/999999").status_code, 404),
    ("mass assignment",   call(TOKEN_B, "PATCH", "/api/profile", json={"display_name": "x", "is_admin": True}).status_code, 200),
]
bad = [(n, got, exp) for n, got, exp in cases if got != exp]
print("mismatches:", bad)
assert call(TOKEN_B, "GET", "/api/profile").json()["is_admin"] is False, "is_admin was settable"
```

## Verification

- Foreign and missing reads return the same status, which is the authorisation and enumeration check.
- The mass-assignment assertion fails when the endpoint uses `setattr` over a dict.
- Re-running after the fix passes without loosening the 404 shape, so the probe stays meaningful.
