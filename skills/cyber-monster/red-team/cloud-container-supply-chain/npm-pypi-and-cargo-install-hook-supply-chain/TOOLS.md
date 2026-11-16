# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`npm-pypi-and-cargo-install-hook-supply-chain`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `npm` | `npm ci --ignore-scripts --dry-run` | The install plan without executing lifecycle scripts | Node |
| `npm` | `npm ls --all --json` | The resolved dependency tree for script review | Node |
| `rg` | `rg -n "ignore-scripts" .github/ .npmrc` | Whether the pipeline disables scripts at all | any |
| `socket` | `socket npm install PACKAGE` | Per-package behaviour analysis including install scripts | Node |
| `osv-scanner` | `osv-scanner --lockfile package-lock.json` | Known-malicious and vulnerable packages against OSV | Go binary |

## Minimal script shape

```python
# Report the blast radius: scripts that can run plus credentials in scope.
import json
import os
import pathlib

CRED = ("TOKEN", "KEY", "SECRET", "AWS_", "AZURE_", "GOOGLE_", "NPM_")

def scripts(root: str) -> list[tuple[str, str]]:
    out = []
    for lock in pathlib.Path(root).rglob("package-lock.json"):
        data = json.loads(lock.read_text(errors="ignore"))
        for name, meta in data.get("packages", {}).items():
            if name and meta.get("hasInstallScript"):
                out.append((name, meta.get("version", "?")))
    return out

def credentials() -> list[str]:
    return sorted(k for k in os.environ if any(c in k.upper() for c in CRED))

if __name__ == "__main__":
    print({"install_scripts": scripts("."), "credential_vars": credentials()})
```

Both non-empty is the finding: the scripts can run and there is something worth stealing. Either alone is a weaker note.
