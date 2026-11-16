# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`session-and-token-lifecycle`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl (cookie jar)` | `curl -sS -c jar -b jar -i 'https://target.example/login' -d 'user=a&pass=b'` | Capture the exact Set-Cookie attributes and reuse the jar across lifecycle events | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' -b 'session=<captured>' 'https://target.example/account'` | Replay a captured identifier after logout or rotation and read the authorised or denied code | Cross-platform |
| `Burp Suite` | `Use the session tracer and 'Request in browser' to diff pre and post-event cookies` | Compare identifier acceptance across logout and password change on one connection | Cross-platform |
| `jq` | `jq ".cookies[]" cookies.json` | Dump exported cookie objects so secure, httpOnly, and sameSite can be audited together | Cross-platform |

## Minimal Script Shape

A revocation harness: it hits a protected route with a captured cookie, calls logout, then replays the same cookie and reports whether invalidation was enforced server-side.

```python
import urllib.error
import urllib.request

PROTECTED = "https://target.example/account"
LOGOUT = "https://target.example/logout"


def authed(cookie):
    req = urllib.request.Request(PROTECTED, headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200
    except urllib.error.HTTPError as exc:
        return exc.code == 200


def logout(cookie):
    req = urllib.request.Request(LOGOUT, data=b"", headers={"Cookie": cookie})
    try:
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError:
        pass


captured = "session=<captured-after-login>"
before = authed(captured)
logout(captured)
after = authed(captured)
print({"before_logout": before, "after_logout": after,
       "server_side_revocation": before and not after})
```
