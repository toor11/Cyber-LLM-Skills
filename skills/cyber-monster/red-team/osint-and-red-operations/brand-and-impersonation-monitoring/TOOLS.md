# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`brand-and-impersonation-monitoring`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** pattern generation over brand strings, CT lookups, and HTTP content comparison with screenshot hashing.
- **Validation Gate:** one candidate traced from pattern match through certificate and content differential.
- Do not interact with a suspected phishing login form; record the form action and the page hash, and hand the URL to the takedown process.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{url_effective}\n' https://candidate.example/` | Check whether a candidate resolves and serves content | Cross-platform |
| `openssl s_client` | `openssl s_client -connect candidate.example:443 -servername candidate.example </dev/null` | Read the candidate certificate subject and dates | Cross-platform |
| `jq` | `jq -r ".[].name_value" ct.json` | Extract names from a certificate transparency response; unique-sort them before comparing | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import hashlib
import json
import sqlite3

con = sqlite3.connect("brand.db")
con.execute("CREATE TABLE IF NOT EXISTS candidate (id INTEGER PRIMARY KEY, url TEXT, pattern TEXT, cert_cn TEXT, content_hash TEXT, form_action TEXT, screenshot_sha256 TEXT)")
for row in con.execute("SELECT url, pattern, cert_cn, content_hash, form_action FROM candidate"):
    print(json.dumps(dict(zip(("url", "pattern", "cert_cn", "content_hash", "form_action"), row))))
```
