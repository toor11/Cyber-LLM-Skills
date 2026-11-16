# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`bug-bounty-and-vdp-workflow`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `subfinder` | `subfinder -d example.com -silent` | Enumerate candidate hosts under the programme domain to triage against scope | Cross-platform |
| `httpx` | `httpx -l hosts.txt -sc -title` | Confirm which enumerated hosts are live before matching them to the scope allowlist | Cross-platform |
| `jq` | `jq ".data[].structured_scopes[].eligible_for_submission" scope.json` | Read the eligibility flag on each authoritative scope asset | Cross-platform |

## Minimal Script Shape

A scope gate: it parses each candidate target and reports whether its host is in scope by exact or registrable-domain match against the programme allowlist, before any testing.

```python
import sys
from urllib.parse import urlsplit

IN_SCOPE = {"example.com", "api.example.com"}
WILDCARDS = {"example.com"}

def registrable(host):
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()

def in_scope(host):
    host = host.lower().strip(".")
    return host in IN_SCOPE or registrable(host) in WILDCARDS

for arg in sys.argv[1:]:
    parsed = urlsplit(arg if "//" in arg else "//" + arg)
    host = parsed.hostname or arg
    print({"target": host, "verdict": "IN_SCOPE" if in_scope(host) else "OUT_OF_SCOPE"})
```
