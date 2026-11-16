# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`username-and-account-pivot-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a candidate table with `service`, `url`, `signal`, `strength`, `observed_at`.
- **Validation Gate:** a strength tally showing which candidates have a second signal.
- Respect each service's terms and robots policy; enumeration that violates them is not usable evidence.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `git` | `git log --format="%ae %an"` | Technical pivot from an email to repositories; unique-sort the lines before correlating | Cross-platform |
| `gpg` | `gpg --search-keys user@target.example` | Key identity as a pivot anchor | Cross-platform |
| `exiftool` | `exiftool -a -G1 -s avatar.jpg` | Metadata before hashing an avatar | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import sqlite3

con = sqlite3.connect("osint.db")
rows = con.execute("SELECT service, handle, signal, strength FROM candidate").fetchall()
out = [{"service": s, "handle": h, "signal": g, "strength": st,
        "status": "confirmed" if st == "strong" else "candidate"} for s, h, g, st in rows]
print(json.dumps(out, indent=2))
```
