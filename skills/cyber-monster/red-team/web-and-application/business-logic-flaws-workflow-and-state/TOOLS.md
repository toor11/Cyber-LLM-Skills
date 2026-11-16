# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`business-logic-flaws-workflow-and-state`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -b jar.txt -X POST 'https://target.example/checkout/confirm'` | Call transitions directly and out of order, bypassing the UI's step sequencing | Cross-platform |
| `Burp Suite Repeater` | `Resend a completed step request or reorder two transition requests` | Replay a one-time step and observe whether its effect compounds | Cross-platform |
| `jq` | `jq .status <(curl -sS https://target.example/orders/1001)` | Read the persisted server-side status so the finding rests on stored state, not UI | Cross-platform |

## Minimal Script Shape

A transition-guard harness: it calls a gated transition without its prerequisite, then reads the persisted record to decide whether the from-state check is missing.

```python
import json
import urllib.error
import urllib.request

BASE = 'https://target.example'
HEADERS = {'Cookie': 'session=<authorised-session>'}

def call(path, method='POST'):
    req = urllib.request.Request(BASE + path, data=b'', method=method, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

def status(order_id):
    req = urllib.request.Request(BASE + '/orders/' + order_id, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read()).get('status')

call('/orders/demo/confirm')
reached = status('demo')
print({'reached_status': reached,
       'transition_guard_missing': reached in ('paid', 'confirmed', 'shipped')})
```
