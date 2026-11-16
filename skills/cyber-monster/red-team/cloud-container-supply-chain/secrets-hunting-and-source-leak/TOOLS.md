# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`secrets-hunting-and-source-leak`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `gitleaks` | `gitleaks detect --source . --report-format json` | Working-tree and history findings with rule ids and line numbers | Go binary |
| `trufflehog` | `trufflehog git file://. --only-verified` | Verified credentials only, which is the precision step built in | Go binary |
| `git` | `git log --all -p -S 'AKIA' -- .` | History search for a specific pattern without a scanner | git |
| `docker` | `docker save IMAGE -o img.tar` | Layer extraction for image-content review | Docker CLI |
| `aws` | `aws sts get-caller-identity` with the candidate credentials | Whether an AWS key pair is live and which principal it is | AWS CLI v2 |

## Minimal script shape

```python
# Triage candidates by provider format before any network verification.
import re
from dataclasses import dataclass

FORMATS = {
    "aws_access_key": re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$"),
    "github_pat": re.compile(r"^ghp_[A-Za-z0-9]{36}$"),
    "github_fine": re.compile(r"^github_pat_[A-Za-z0-9_]{82}$"),
    "slack": re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

@dataclass
class Candidate:
    path: str
    line: int
    value: str

def classify(cands: list[Candidate]) -> list[dict]:
    out = []
    for c in cands:
        for name, pat in FORMATS.items():
            if pat.search(c.value.strip()):
                out.append({"path": c.path, "line": c.line, "kind": name})
                break
    return out

if __name__ == "__main__":
    print(classify([Candidate(".env", 3, "AKIA" + "A" * 16)]))
```

Only candidates that pass a format check proceed to verification; the `kind` determines which read-only endpoint is appropriate.
