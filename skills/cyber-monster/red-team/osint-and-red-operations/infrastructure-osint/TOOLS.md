# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`infrastructure-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** RDAP JSON, routing registry queries, certificate transparency JSON, and banner data; each retrieval stored with a timestamp.
- **Validation Gate:** one attributed asset traced end to end from registrant handle to announced prefix to certificate subject.
- Certificate transparency retrieval APIs differ; a client pointed at an RFC 6962 endpoint may return nothing for current logs, so record which interface answered.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://crt.sh/?q=%25.target.example&output=json'` | Certificate transparency names for a domain | Cross-platform |
| `whois` | `whois -h whois.radb.net -- '-i origin AS64500'` | Announced prefixes for an ASN from a routing registry | Cross-platform |
| `dig` | `dig +short CNAME target.example` | Confirm whether a name is hosted elsewhere | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import sqlite3

con = sqlite3.connect("osint.db")
con.execute("CREATE TABLE IF NOT EXISTS asset (id INTEGER PRIMARY KEY, name TEXT, evidence TEXT, retrieved_at TEXT)")
rows = con.execute("SELECT name, evidence, retrieved_at FROM asset").fetchall()
for name, evidence, at in rows:
    print(json.dumps({"asset": name, "evidence": evidence, "retrieved_at": at}))
```
