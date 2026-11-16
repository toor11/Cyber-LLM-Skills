# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`csrf`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i -X POST 'https://target.example/account/email' -H 'Cookie: session=<victim>' -H 'Origin: https://assessor.example' --data 'email=assessor%40example.org'` | Replays the exact request shape with an explicit foreign Origin so the decision is visible in the response | Cross-platform |
| `Burp Suite Repeater` | `Right-click request, 'Engagement tools > Generate CSRF PoC'` | Produces the minimal cross-site form that reproduces the captured request without script | Cross-platform |
| `Playwright` | `npx playwright codegen https://assessor.example` | Drives a real browser through the foreign-origin page so cookie policies are exercised as a browser would | Cross-platform |
| `curl (cookie jar)` | `curl -sS -c jar.txt -b jar.txt 'https://target.example/login' -d 'user=a&pass=b'` | Captures the actual Set-Cookie attributes for the session, which is where the SameSite decision is recorded | Cross-platform |

## Minimal Script Shape

A differential harness: it performs the same state-changing request twice, once with a same-origin Origin and once with a foreign one, and reports whether the server distinguished them.

```python
import urllib.parse
import urllib.request

ENDPOINT = "https://target.example/account/email"
BODY = urllib.parse.urlencode({"email": "assessor@example.org"}).encode()

def post(origin, cookie):
    req = urllib.request.Request(ENDPOINT, data=BODY, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Origin", origin)
    req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

cookie = "session=<victim-session-value>"
same = post("https://target.example", cookie)
foreign = post("https://assessor.example", cookie)
print({"same_origin": same, "foreign_origin": foreign,
       "origin_check_enforced": same != foreign and foreign in (401, 403)})
```
