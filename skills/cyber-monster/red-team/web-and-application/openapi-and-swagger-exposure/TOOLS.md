# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`openapi-and-swagger-exposure`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS --range 0-399 -o spec-head.txt https://target.example/v3/api-docs` | Save the opening bytes of a spec and confirm a document is returned anonymously | Cross-platform |
| `ffuf` | `ffuf -u https://target.example/FUZZ -w swagger-paths.txt -mc 200` | Enumerate common spec and UI paths to locate the disclosure endpoint | Cross-platform |
| `python` | `python docs_probe.py https://target.example` | Fetch candidate doc paths and flag which return a parseable specification | Cross-platform |

## Minimal Script Shape

A specification prober: it requests the common doc paths and reports which respond with a document that parses as an OpenAPI or Swagger inventory.

```python
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://target.example"
PATHS = ["/v3/api-docs", "/openapi.json", "/swagger.json", "/swagger-ui/index.html"]

def probe(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(2048).decode("utf-8", "replace")
            is_spec = "openapi" in body or "swagger" in body
            return path, r.status, is_spec
    except Exception as exc:
        return path, getattr(exc, "code", "ERR"), False

for p in PATHS:
    print(probe(p))
```
