# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cross-site-scripting-stored`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -X POST https://target.example/comments -d 'body=zz9s2trace<u>probe</u>'` | Store the tracer so the write-then-read render path can then be inspected | Cross-platform |
| `Burp Suite` | `Use the site map 'search' to find every response containing the stored tracer` | Reveals all render paths that emit the stored field, including privileged views | Cross-platform |
| `Playwright` | `npx playwright open https://target.example/admin/queue` | Loads a privileged render path in a real browser to confirm the stored node parsed | Cross-platform |

## Minimal Script Shape

A stored-render harness: it persists a tracer probe, then loads several candidate read paths and reports which render it and whether an inert tag survived un-encoded.

```python
import urllib.parse
import urllib.request

WRITE = "https://target.example/comments"
READ_PATHS = ["https://target.example/post/1", "https://target.example/admin/queue"]
TRACER = "zz9s2trace"
PROBE = TRACER + "<u>probe</u>"

def post(body):
    data = urllib.parse.urlencode({"body": body}).encode()
    req = urllib.request.Request(WRITE, data=data, method="POST",
                                 headers={"User-Agent": "authorised-assessment"})
    urllib.request.urlopen(req, timeout=10).read()

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

post(PROBE)
for url in READ_PATHS:
    body = get(url)
    print({"read_path": url, "tracer_present": TRACER in body,
           "tag_survived_unencoded": PROBE in body})
```
