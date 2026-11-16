# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`adversary-emulation-planning`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** ATT&CK technique ids, a plan table with expected telemetry and verdicts, and a deconfliction window agreed with the SOC.
- **Validation Gate:** one telemetry source proven to produce events before any verdict is recorded.
- ATT&CK technique ids are stable; sub-technique ids change more often, so record the parent id when the plan must survive mapping updates.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sqlite3` | `sqlite3 emulation.db ".schema steps"` | Confirm the plan schema holds technique, telemetry and verdict | Cross-platform |
| `jq` | `jq ".[].technique" plan.json` | Review technique ids in the plan table before execution | Linux, macOS |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' https://attack.example/` | Check reachability of a technique reference mirror | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import sqlite3

con = sqlite3.connect("emulation.db")
con.execute("CREATE TABLE IF NOT EXISTS steps (id INTEGER PRIMARY KEY, technique TEXT, expected TEXT, source TEXT, detection TEXT, fired INTEGER)")
rows = con.execute("SELECT technique, expected, source, detection, fired FROM steps").fetchall()
for t, e, s, d, f in rows:
    print(json.dumps({"technique": t, "expected": e, "source": s, "detection": d,
                      "verdict": "covered" if f else "gap"}))
```
