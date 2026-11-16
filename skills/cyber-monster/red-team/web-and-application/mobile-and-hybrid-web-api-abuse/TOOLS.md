# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`mobile-and-hybrid-web-api-abuse`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mitmproxy` | `mitmproxy --mode regular -w flows.mitm` | Capture the app's authenticated API requests so they can be replayed outside the app | Linux, macOS, Windows |
| `apktool` | `apktool d app.apk -o app_src` | Unpack the Android bundle to recover hardcoded keys and hidden base URLs | Cross-platform |
| `curl` | `curl -sS -i -H 'Authorization: Bearer <tester-token>' 'https://api.target.example/v1/orders/<tester-B-id>'` | Replay a captured request with one changed id to test object-level authorisation | Cross-platform |
| `ffuf` | `ffuf -w routes.txt -u https://api.target.example/FUZZ -H 'Authorization: Bearer <tester-token>' -mc 200,201` | Enumerate debug, internal, and versioned routes the app never calls | Cross-platform |

## Minimal Script Shape

A BOLA differential harness: it fetches the tester's own object and then another tester account's object with the same token, flagging a likely object-level authorisation gap when both return data.

```python
import urllib.request

API = "https://api.target.example/v1/orders/"
TOKEN = "Bearer <tester-A-token>"

def fetch(object_id):
    req = urllib.request.Request(API + object_id)
    req.add_header("Authorization", TOKEN)
    req.add_header("User-Agent", "authorised-assessment")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, 0

own = fetch("<tester-A-id>")
other = fetch("<tester-B-id>")
print({"own": own, "other": other,
       "bola_suspected": other[0] == 200 and other[1] > 0})
```
