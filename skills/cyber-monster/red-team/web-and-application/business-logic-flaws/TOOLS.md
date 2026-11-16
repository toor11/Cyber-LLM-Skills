# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`business-logic-flaws`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -b jar.txt 'https://target.example/api/quote?sku=ABC&quantity=1'` | Capture the authoritative total the server returns for an intended-path request as the differential baseline | Cross-platform |
| `Burp Suite Repeater` | `Send the quote request to Repeater and toggle one field (quantity, price, status) between runs` | Hold every field constant except the rule-breaking one so the authoritative-value change is attributable | Cross-platform |
| `Turbo Intruder` | `queueRequest with a race-sync group to release N identical redemptions together` | Drive the concurrency class so a non-atomic read-decide-increment is exposed | Cross-platform |
| `jq` | `jq ".total_cents, .status, .balance_cents" <(curl -sS https://target.example/api/order)` | Extract the authoritative server-side fields so comparison is on stored values, not the rendered page | Cross-platform |

## Minimal Script Shape

A paired-quote harness: it requests the operation the intended way and with one rule-breaking field, then compares the authoritative value from the JSON response. It reports a logic flaw only when the server-side total moves.

```python
import json
import urllib.parse
import urllib.request

ENDPOINT = 'https://target.example/api/quote'
FIELD = 'total_cents'

def quote(params):
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(ENDPOINT, data=data, method='POST')
    req.add_header('Cookie', 'session=<authorised-session>')
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read()).get(FIELD)

baseline = quote({'sku': 'ABC', 'quantity': '1'})
probe = quote({'sku': 'ABC', 'quantity': '-1'})
print({'baseline': baseline, 'probe': probe,
       'logic_flaw': probe is not None and baseline is not None and probe < baseline})
```
