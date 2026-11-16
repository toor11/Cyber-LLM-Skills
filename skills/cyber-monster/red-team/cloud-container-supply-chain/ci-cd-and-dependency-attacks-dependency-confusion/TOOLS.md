# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ci-cd-and-dependency-attacks-dependency-confusion`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `npm` | `npm config list --location=project` | The effective registry configuration, including scope mapping | Node |
| `npm` | `npm view PKG versions --registry=https://registry.npmjs.org/` | Whether a name exists publicly, without installing | Node |
| `pip` | `pip config list` | The effective index configuration | Python |
| `pip` | `pip download PKG --index-url URL --no-deps -d /tmp/x` | Confirms which index serves a name | Python |
| `pip-compile` | `pip-compile --generate-hashes requirements.in` | Produces a hash-pinned lock, which is the fix | pip-tools |

## Minimal script shape

```python
# Classify resolver configuration by fallback risk.
import pathlib
import re

SCOPE_PIN = re.compile(r"^@[\w.-]+:registry\s*=\s*(\S+)", re.M)
DEFAULT = re.compile(r"^registry\s*=\s*(\S+)", re.M)
EXTRA_INDEX = re.compile(r"extra-index-url\s*=?\s*(\S+)", re.M)
HASHES = re.compile(r"--hash=sha256:")

def npm_risk(root: str) -> dict:
    rc = pathlib.Path(root) / ".npmrc"
    if not rc.exists():
        return {"npmrc": False, "risk": "no project .npmrc; inherits user config"}
    text = rc.read_text(errors="ignore")
    return {"npmrc": True, "default": bool(DEFAULT.search(text)),
            "scope_pins": SCOPE_PIN.findall(text),
            "risk": "public_fallback" if DEFAULT.search(text) and not SCOPE_PIN.search(text) else "pinned"}

def pip_risk(root: str) -> dict:
    for name in ("requirements.txt", "requirements.in"):
        p = pathlib.Path(root) / name
        if p.exists():
            text = p.read_text(errors="ignore")
            return {"file": name, "extra_index": bool(EXTRA_INDEX.search(text)),
                    "hashes": bool(HASHES.search(text))}
    return {"file": None}

if __name__ == "__main__":
    print(npm_risk("."), pip_risk("."))
```

`risk: public_fallback` or `extra_index: True` with `hashes: False` is the finding; the returned config values are what the report quotes.
