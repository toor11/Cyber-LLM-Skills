# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`supply-chain-attack-recon`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `npm` | `npm view PKG time --json` | Publish history, which shows cadence anomalies | Node |
| `npm` | `npm view PKG maintainers --json` | Maintainer list and count | Node |
| `socket` | `socket package score PKG` | Supply-chain risk signals per package | Node |
| `deps.dev` | `curl -s "https://api.deps.dev/v3/systems/npm/packages/PKG"` | Dependency and advisory metadata without a local install | any |
| `rg` | `rg -n -e 'runs-on:' -e 'secrets\.' .github/workflows/` | Build-path exposure in public source | any |

## Minimal script shape

```python
# Report concentration: packages referenced widely with few maintainers.
import json
import subprocess

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True).stdout

def maintainers(pkg: str) -> int:
    out = sh("npm", "view", pkg, "maintainers", "--json")
    try:
        return len(json.loads(out))
    except Exception:
        return -1

def concentration(packages: list[str]) -> list[dict]:
    rows = []
    for p in packages:
        rows.append({"package": p, "maintainers": maintainers(p)})
    return sorted(rows, key=lambda r: r["maintainers"])

if __name__ == "__main__":
    for row in concentration(["@acme/critical-lib", "tiny-invariant"]):
        if 0 <= row["maintainers"] <= 1:
            print("CONCENTRATION", row)
```

A `maintainers` count of 0 or 1 on a package in the critical path is the finding; the report pairs it with the publish-token scope from the CI configuration.
