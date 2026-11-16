# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`social-engineering-and-pretexting-voice-and-message-based`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a script with an explicit disclosure line, an approved caller identity, and a contact log with `step_tested`, `callback_performed`, `disclosure_given`, `debriefed_at`.
- **Validation Gate:** a rehearsal call to the assessment team confirming the disclosure line and logging path.
- Do not record calls unless the authorisation explicitly permits recording; a contact log is sufficient evidence.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import yaml; d=yaml.safe_load(open('vishing-scope.yaml')); print(d['caller_id'], d['disclosure_line'])"` | Confirm caller identity and disclosure line before dialling | Cross-platform |
| `sqlite3` | `sqlite3 vishing.db "SELECT COUNT(*) FROM call WHERE debriefed_at IS NULL;"` | List contacts awaiting debrief | Cross-platform |
| `date` | `date -u +%Y-%m-%dT%H:%M:%SZ` | Timestamp each contact in UTC | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import sqlite3

con = sqlite3.connect("vishing.db")
con.execute("CREATE TABLE IF NOT EXISTS call (id INTEGER PRIMARY KEY, at TEXT, identity TEXT, step_tested TEXT, callback_performed INTEGER, disclosure_given INTEGER, debriefed_at TEXT)")
for step, n, misses in con.execute("""
    SELECT step_tested, COUNT(*), SUM(callback_performed = 0) FROM call GROUP BY step_tested
"""):
    print(step, n, "control not performed", misses or 0)
```
