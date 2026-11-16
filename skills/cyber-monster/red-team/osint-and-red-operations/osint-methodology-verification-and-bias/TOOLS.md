# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`osint-methodology-verification-and-bias`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a corroboration table keyed by claim and origin, with an independence flag and a falsifier-attempt column.
- **Validation Gate:** a query returning distinct origins per claim before the report is finalised.
- Record the retrieval date for each corroborating source; corroboration across different dates can hide a change in the underlying fact.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sqlite3` | `sqlite3 osint.db "SELECT claim, COUNT(DISTINCT origin) FROM corroboration GROUP BY claim;"` | Count independent origins per claim | Cross-platform |
| `curl` | `curl -sS -D- -o /dev/null https://news.example/article` | Confirm the publishing origin and date of a corroborating page | Cross-platform |
| `dig` | `dig +short NS target.example` | Technical corroboration independent of documentary sources | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import sqlite3

con = sqlite3.connect("osint.db")
for claim, sources, origins in con.execute("""
    SELECT claim, COUNT(*) AS sources, COUNT(DISTINCT origin) AS origins
    FROM corroboration GROUP BY claim
"""):
    verdict = "single-sourced" if origins < 2 else "corroborated"
    print(f"{claim}: {sources} sources / {origins} origins -> {verdict}")
```
