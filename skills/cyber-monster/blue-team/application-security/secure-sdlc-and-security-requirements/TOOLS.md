# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`secure-sdlc-and-security-requirements`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `git` | `git log --grep 'ASVS-' --oneline -n 50` | Show which requirement ids actually appear in change history | Cross-platform |
| `gh` / `glab` | `gh run list --workflow security.yml --limit 50 --json conclusion,headSha` | Evidence gate outcomes per commit | Cross-platform |
| `semgrep` | `semgrep scan --config p/owasp-top-ten --error --sarif -o out.sarif` | Serve as the enforcement half of a coding requirement | Cross-platform |
| `opa` | `opa eval -d policy/ -i input.json 'data.release.allow'` | Evaluate a release policy against gathered evidence | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, subprocess, sys

REQ = {"ASVS-1.2.4": "tests/security/test_sqli.py::test_parameterised_only",
       "ASVS-16.2.1": "tests/security/test_audit_log.py::test_auth_events"}

def runs():
    out = subprocess.run(["gh", "run", "list", "--workflow", "security.yml", "--limit", "50",
                          "--json", "conclusion,headSha,displayTitle"], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)

probes = [r for r in runs() if "gate-probe" in r["displayTitle"]]
print("gate probe runs:", len(probes), "failures:", sum(r["conclusion"] != "success" for r in probes))
missing = [k for k, v in REQ.items() if not subprocess.run(["git", "grep", "-q", k, "--", v]).returncode == 0]
print("requirements without a citing test:", missing)
sys.exit(0 if probes and not missing else 1)
```

## Verification

- The script exits non-zero when a requirement id is removed from its test, which is the regression it exists to catch.
- `gh run list` output parses, proving the token has workflow read scope before you rely on it.
- Probe run count is non-zero for every blocking workflow name in the register.
