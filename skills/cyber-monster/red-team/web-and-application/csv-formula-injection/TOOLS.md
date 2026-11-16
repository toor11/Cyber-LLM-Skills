# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`csv-formula-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `csv exporter` | `Trigger the export, then open the raw .csv in a text editor` | Reads the leading cell bytes directly to see whether a user value begins with a trigger | Cross-platform |
| `unzip + xmllint` | `unzip -p export.xlsx xl/sharedStrings.xml > sharedStrings.xml` | Write XLSX string cells to a file, then format that file with xmllint and check whether a user value begins with a trigger | Linux, macOS, Windows |
| `CSVScan` | `csvscan export.csv` | WOOT'25 scanner that flags cells a spreadsheet client would evaluate as formulas | Linux, macOS |
| `OWASP WSTG manual check` | `Export, open in a spreadsheet client in a sandbox VM, observe the probe cell` | Confirms on-open evaluation of the probe cell without touching production | Cross-platform |

## Minimal Script Shape

An export-neutralisation checker: it writes a benign control and a trigger probe through the CSV writer, reads the serialised cells back, and flags any cell whose first character is a formula trigger.

```python
import csv
import io

TRIGGERS = ("=", "+", "-", "@", "\t", "\r")
ROWS = [
    {"name": "alice", "note": "zzcsv_control_text"},
    {"name": "bob", "note": "=1+1"},
]

buf = io.StringIO()
writer = csv.writer(buf)
writer.writerow(["name", "note"])
for r in ROWS:
    writer.writerow([r["name"], r["note"]])

buf.seek(0)
reader = csv.reader(buf)
header = next(reader)
flagged = []
for row in reader:
    for col, cell in zip(header, row):
        if cell[:1] in TRIGGERS:
            flagged.append({"column": col, "cell": cell[:16]})
print({"formula_trigger_cells": flagged,
       "verdict": "VULNERABLE export" if flagged else "neutralised"})
```
