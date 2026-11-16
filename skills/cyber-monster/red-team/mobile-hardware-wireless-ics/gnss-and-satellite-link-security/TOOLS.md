# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`gnss-and-satellite-link-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `gpsd` | `gpsmon` / `cgps` | Receiver-reported position, time, and mode flags | POSIX |
| `gpspipe` | `gpspipe -w -n 5` | JSON view including fix quality and satellite set | POSIX |
| `rg` | `rg -i -e 'osnma' -e 'gsc' gnss-driver/` | Whether the receiver implements authentication | any |
| `chronyc` | `chronyc tracking` | The system clock's source and its agreement, which is the cross-check | Linux |

## Minimal script shape

```python
# Report the trust chain from receiver to consumer for time and position.
import re
import pathlib

CONSUMERS = {
    "time_security": re.compile(r"(not_valid|expire|tls|token).*gnss|gnss.*(not_valid|expire)", re.I),
    "position_decision": re.compile(r"(geofence|billing|route|alarm).*position|position.*(geofence|billing)", re.I),
}
OSNMA = re.compile(r"osnma", re.I)
CROSSCHECK = re.compile(r"(ntp|chrony|trusted_utc|second_source)", re.I)

def assess(root: str) -> dict:
    out = {"osnma": 0, "crosscheck": 0, "consumers": []}
    for p in pathlib.Path(root).rglob("*.py"):
        t = p.read_text(errors="ignore")
        out["osnma"] += len(OSNMA.findall(t))
        out["crosscheck"] += len(CROSSCHECK.findall(t))
        for name, pat in CONSUMERS.items():
            if pat.search(t):
                out["consumers"].append({"file": str(p), "kind": name})
    return out

if __name__ == "__main__":
    print(assess("services"))
```

A security consumer with `osnma: 0` and `crosscheck: 0` is the finding; `osnma` present with a `crosscheck` is the control set.
