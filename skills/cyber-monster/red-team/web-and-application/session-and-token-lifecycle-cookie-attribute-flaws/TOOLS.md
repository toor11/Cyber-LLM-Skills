# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`session-and-token-lifecycle-cookie-attribute-flaws`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D headers.txt -o body.txt https://target.example/login -d "user=a&pass=b"` | Save response headers, then read Set-Cookie in headers.txt for the issued attributes | Cross-platform |
| `Chrome DevTools` | `Application, Storage, Cookies; inspect the HttpOnly, Secure, SameSite, Domain, and Path columns` | Confirm the browser-parsed attributes rather than the documented ones | Cross-platform |
| `curl` | `curl -sS -i 'http://target.example/account' -b 'session=<captured>'` | Check whether the cookie is accepted over cleartext, proving Secure is absent | Cross-platform |
| `audit script` | `python audit_cookies.py https://target.example` | Batch-flag session cookies missing Secure, HttpOnly, or SameSite or using a broad Domain | Cross-platform |

## Minimal Script Shape

A Set-Cookie auditor: it parses the login response cookies and reports which binding attributes are missing so a weak session cookie is flagged without a browser.

```python
import http.cookies
import sys
import urllib.request


def issued_attrs(url):
    req = urllib.request.Request(url, data=b"user=a&pass=b")
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.headers.get_all("Set-Cookie") or []
    findings = []
    for line in raw:
        c = http.cookies.SimpleCookie(line)
        for name, morsel in c.items():
            findings.append({
                "name": name,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or "ABSENT",
                "domain": morsel["domain"] or "host-only",
            })
    return findings


if __name__ == "__main__":
    for f in issued_attrs(sys.argv[1]):
        weak = not f["secure"] or not f["httponly"] or f["samesite"] == "ABSENT"
        print(f, "WEAK" if weak else "ok")
```
