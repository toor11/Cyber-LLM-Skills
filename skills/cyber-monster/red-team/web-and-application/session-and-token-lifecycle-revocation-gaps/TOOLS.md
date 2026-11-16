# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`session-and-token-lifecycle-revocation-gaps`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer <captured>' 'https://target.example/api/profile'` | Replay a captured bearer token after a revocation event and read the authorised or denied code | Cross-platform |
| `curl (cookie jar)` | `curl -sS -c jar -b jar 'https://target.example/logout'; curl -sS -b jar 'https://target.example/api/profile'` | Exercise logout then immediately reuse the same jar to test server-side invalidation | Cross-platform |
| `jwt-cli` | `jwt decode <captured>` | Read the expiry and unique id to judge whether a denylist or only expiry limits reuse | Cross-platform |
| `Burp Suite Repeater` | `Replay the authenticated request before and after triggering each revocation event` | Compare acceptance across logout, password change, and disable on one connection | Cross-platform |

## Minimal Script Shape

A logout-replay harness: it calls a protected API with a captured token, triggers logout, replays the token, and reports whether revocation actually took effect.

```python
import urllib.error
import urllib.request

API = "https://target.example/api/profile"
LOGOUT = "https://target.example/logout"


def call(token):
    req = urllib.request.Request(API, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code


def do_logout(token):
    req = urllib.request.Request(LOGOUT, data=b"", headers={"Authorization": "Bearer " + token})
    try:
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError:
        pass


if __name__ == "__main__":
    token = "<captured-access-token>"
    before = call(token)
    do_logout(token)
    after = call(token)
    print({"before_logout": before, "after_logout": after,
           "revocation_effective": before == 200 and after != 200})
```
