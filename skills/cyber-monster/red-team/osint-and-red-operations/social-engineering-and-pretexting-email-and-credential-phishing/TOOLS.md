# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`social-engineering-and-pretexting-email-and-credential-phishing`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** an authorised domain or platform tenant, a landing page configured to log events only, and a recipient/event database for results.
- **Validation Gate:** a test message to an internal address confirming the landing page records an event without storing field values.
- Configure the landing page to discard request bodies; logging the body is the most common accidental secret capture.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import yaml; print(yaml.safe_load(open('phish-scope.yaml'))['sending_domain'])"` | Confirm the authorised sending domain | Cross-platform |
| `email` | `python -c "import email; m=email.message_from_bytes(open('sample.eml','rb').read()); print(m['Received'])"` | Read delivery headers to verify the sending path | Cross-platform |
| `sqlite3` | `sqlite3 phish.db "SELECT action, COUNT(*) FROM event GROUP BY action;"` | Tally landing events per action | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import sqlite3

con = sqlite3.connect("phish.db")
con.execute("CREATE TABLE IF NOT EXISTS event (id INTEGER PRIMARY KEY, recipient TEXT, cohort TEXT, at TEXT, action TEXT, debriefed_at TEXT)")
for action, n, open_debrief in con.execute("""
    SELECT action, COUNT(*), SUM(debriefed_at IS NULL) FROM event GROUP BY action
"""):
    print(action, n, "awaiting debrief", open_debrief or 0)
```
