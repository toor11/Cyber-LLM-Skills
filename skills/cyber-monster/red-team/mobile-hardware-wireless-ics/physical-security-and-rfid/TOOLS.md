# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`physical-security-and-rfid`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `proxmark3` | `proxmark3 /dev/ttyACM0 -c "lf search"` | Card technology identification in listen-only mode | proxmark3 |
| `nfcpy` | `python -c "import nfc; print(nfc.ContactlessFrontend('usb'))"` | NFC reader presence and basic card discovery | Python |
| `rg` | `rg -n "rule=card" access-export.csv` | Controller rules per zone, from an export | any |
| `pcsc_scan` | `pcsc_scan` | Card ATR, which identifies the card family | pcsc-tools |

## Minimal script shape

```python
# Classify an access-control export into finding or control per zone.
import csv
from dataclasses import dataclass

SENSITIVE = {"server-room", "cash-office", "pharmacy", "evidence-store"}

@dataclass
class Rule:
    zone: str
    factors: str
    schedule: str

def classify(rows: list[Rule]) -> list[dict]:
    out = []
    for r in rows:
        single = r.factors.strip().lower() in ("card", "fob", "badge")
        out.append({"zone": r.zone, "sensitive": r.zone in SENSITIVE,
                    "single_factor": single,
                    "finding": r.zone in SENSITIVE and single})
    return out

if __name__ == "__main__":
    rows = [Rule(r["zone"], r["factors"], r["schedule"]) for r in csv.DictReader(open("access-export.csv"))]
    for row in classify(rows):
        if row["finding"]:
            print("SINGLE FACTOR ON SENSITIVE ZONE", row)
```

A printed row is the finding; the zone and the factor list are the evidence, and the remediation is a second factor on that zone.
