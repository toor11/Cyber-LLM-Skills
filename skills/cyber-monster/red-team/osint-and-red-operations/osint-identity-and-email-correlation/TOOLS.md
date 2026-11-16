# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`osint-identity-and-email-correlation`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `gpg` for key lookup and fingerprint verification, `git log --format` for commit author metadata, perceptual hashing for avatars.
- **Validation Gate:** one confirmed second signal per link before it leaves the candidate table.
- Key servers differ in completeness and some are unmaintained; record which server answered so the observation is reproducible.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `gpg` | `gpg --search-keys user@target.example` | Look up a key by address and read its fingerprint | Cross-platform |
| `git` | `git log --format="%ae %an %G?"` | List commit authors with signature status; unique-sort the lines before correlating | Cross-platform |
| `exiftool` | `exiftool -a -G1 avatar.jpg` | Read image metadata before perceptual hashing | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import sqlite3

con = sqlite3.connect("osint.db")
con.execute("CREATE TABLE IF NOT EXISTS link (id INTEGER PRIMARY KEY, anchor TEXT, candidate TEXT, signal TEXT, strength TEXT)")
rows = con.execute("SELECT anchor, candidate, COUNT(DISTINCT signal) FROM link GROUP BY anchor, candidate").fetchall()
for anchor, candidate, n in rows:
    status = "confirmed" if n >= 2 else "candidate"
    print(json.dumps({"anchor": anchor, "candidate": candidate, "signals": n, "status": status}))
```
