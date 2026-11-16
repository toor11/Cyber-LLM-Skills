# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`social-engineering-and-pretexting`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a YAML authorisation naming channels, roles, and impersonated organisations; a contact log and a debrief register.
- **Validation Gate:** zero contacts without a channel entry in the authorisation before the exercise begins.
- Record the agent's identifier where the channel allows it, so the debrief can reach the right person.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import yaml; print(yaml.safe_load(open('se-scope.yaml'))['channels'])"` | Read the authorised channel list | Cross-platform |
| `sqlite3` | `sqlite3 se.db "SELECT * FROM contact WHERE debriefed_at IS NULL;"` | List contacts still awaiting debrief | Cross-platform |
| `date` | `date -u +%Y-%m-%dT%H:%M:%SZ` | Timestamp contacts in UTC for the log | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import sqlite3

con = sqlite3.connect("se.db")
con.execute("CREATE TABLE IF NOT EXISTS contact (id INTEGER PRIMARY KEY, at TEXT, channel TEXT, pretext TEXT, control_tested TEXT, outcome TEXT, debriefed_at TEXT)")
open_items = con.execute("SELECT COUNT(*) FROM contact WHERE debriefed_at IS NULL").fetchone()[0]
print("contacts", con.execute("SELECT COUNT(*) FROM contact").fetchone()[0], "awaiting debrief", open_items)
```
