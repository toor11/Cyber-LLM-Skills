# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`secure-code-review-language-specific-review`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `semgrep` | `semgrep scan --config p/ruby --config p/python --config p/java --config p/php --error` | Language-specific dangerous-construct rules | Cross-platform |
| `brakeman` | `brakeman -q -f json` | Rails-specific deserialisation and mass-assignment candidates | Ruby |
| `bandit` | `bandit -r . -f json -o bandit.json` | Python construct checks including `pickle` and `yaml` | Python |
| `gosec` | `gosec -fmt=json -out gosec.json ./...` | Go path and file handling checks | Go |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, subprocess, sys

findings = []
for cmd, key in ((["bandit", "-r", ".", "-f", "json"], "results"),
                 (["brakeman", "-q", "-f", "json", "--no-pager"], "warnings")):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout
        data = json.loads(out or "{}")
    except (FileNotFoundError, json.JSONDecodeError):
        print("skipped:", cmd[0]); continue
    for item in data.get(key, []):
        findings.append((cmd[0], item.get("test_id") or item.get("check_name"),
                         item.get("filename"), item.get("line_number") or item.get("line")))

for f in findings:
    print("%-8s %-24s %s:%s" % f)
sys.exit(0 if not findings else 1)
```

## Verification

- Both scanners' outputs parse; a scanner that is absent prints `skipped` rather than silently passing the gate.
- Every printed location is opened and dispositioned; the tool list is a candidate generator, not a verdict.
- Re-running after the fix removes the specific id without removing the tool from the gate.
