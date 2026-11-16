# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`password-reset-and-account-recovery`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -X POST "https://target.example/forgot" -H "Host: assessor.example" --data "email=victim@app.example"` | Submit a reset with a foreign Host to see whether the generated link follows it | Cross-platform |
| `Burp Suite Repeater` | `Replay the token acceptance request after a successful reset to test single-use` | Confirm whether a used token is invalidated or still accepted | Cross-platform |
| `python` | `python enum_check.py` | Compare known versus unknown account responses for an enumeration signal | Cross-platform |

## Minimal Script Shape

An enumeration differential harness: it submits the forgot-password endpoint for a known and an unknown address and reports whether status or body length distinguishes them.

```python
import urllib.parse
import urllib.request

ENDPOINT = "https://target.example/forgot"

def submit(email):
    data = urllib.parse.urlencode({"email": email}).encode()
    req = urllib.request.Request(ENDPOINT, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, 0

known = submit("known@app.example")
absent = submit("absent@app.example")
print({"known": known, "absent": absent, "enumeration_signal": known != absent})
```
