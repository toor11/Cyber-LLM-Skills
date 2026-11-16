# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authentication-and-session-design-review`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i -c jar.txt -d 'user=a&pass=b' https://staging/login` | Capture cookies and headers exactly as issued | Cross-platform |
| `jwt-cli` / `jwt` | `jwt decode --json $TOKEN` | Inspect header and claims before writing assertions about them | Cross-platform |
| `nuclei` | `nuclei -u https://staging -t http/misconfiguration/ -severity high,critical` | Catch cookie and header misconfiguration regressions | Cross-platform |
| `pytest` + `httpx` | `pytest -q tests/auth/test_revocation.py` | Encode the replay probe as a regression test | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import httpx

BASE = "https://staging"
def login(c):
    r = c.post(f"{BASE}/login", json={"user": "u1", "pass": "p1"})
    r.raise_for_status()
    return r.cookies

with httpx.Client() as a, httpx.Client() as b:
    login(a); login(b)
    a.post(f"{BASE}/password", json={"old": "p1", "new": "p2"}).raise_for_status()
    probe = b.get(f"{BASE}/me")
    print("second client after password change:", probe.status_code)
    assert probe.status_code == 401, "other sessions survived a password change"
```

## Verification

- The assertion fails on the current build if revocation is missing, which is the finding.
- Re-running after the fix passes and the initiating client still works, so rotation did not log the user out of everything by accident.
- The same shape is reused for role change and logout so the three transitions stay covered.
