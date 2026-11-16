# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sql-injection-orm-and-query-builder`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ripgrep` | `rg -n -e whereRaw -e orderByRaw -e ".extra(" -e RawSQL -e queryRawUnsafe -e "literal(" --type js --type py` | Enumerate raw-fragment builder call sites that bypass ORM escaping | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' 'https://target.example/orders?sort=total'` | Capture status and body size for a benign sort token as the identifier-slot baseline | Cross-platform |
| `sqlmap` | `sqlmap -u 'https://target.example/orders?sort=total' -p sort --technique=B --level=2 --batch` | Confirm a boolean channel specifically on the non-bindable sort parameter | Linux, Windows, macOS |

## Minimal Script Shape

A sort-token harness: it compares a known column against an unknown column token on the same builder-backed endpoint and flags interpolation when their responses diverge.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/orders"

def fetch(sort_token):
    url = BASE + "?" + urllib.parse.urlencode({"sort": sort_token})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, len(r.read())

known = fetch("total")
unknown = fetch("no_such_column_xyz")
print({"known_column": known, "unknown_column": unknown,
       "identifier_interpolated": known != unknown})
```
