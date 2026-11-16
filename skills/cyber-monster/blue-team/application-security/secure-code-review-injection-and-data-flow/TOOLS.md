# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`secure-code-review-injection-and-data-flow`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `semgrep` | `semgrep scan --config p/owasp-top-ten --config p/command-injection --error` | Candidate sinks with rule ids | Cross-platform |
| `semgrep taint` | `semgrep scan --config taint.yml` with `sources`/`sinks` declared | Path-proven flows for one sink class | Cross-platform |
| `sqlmap` | `sqlmap -u 'https://staging/reports?sort=id' --batch --level=1 --risk=1 --technique=B` | Confirm identifier injection on a value that parameters cannot bind, with a bounded run | Cross-platform |
| `ffuf` | `ffuf -w traversal.txt -u 'https://staging/files/FUZZ' -mc all -fs 0` | Differential for path traversal using response size | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import httpx, statistics

BASE = "https://staging/reports"
def timing(params):
    xs = []
    for _ in range(5):
        r = httpx.get(BASE, params=params, timeout=10)
        xs.append((r.status_code, len(r.content)))
    return r.status_code, statistics.median(len(c) for c in [httpx.get(BASE, params=params).content])

benign = {"sort": "id"}
probe = {"sort": "id,(select 1)"}
b = timing(benign); p = timing(probe)
print("baseline:", b, "probe:", p)
print("VERDICT:", "same class" if b[0] == p[0] else "DIFFERENTIAL - review sink")
if b[0] != p[0]:
    raise SystemExit(2)
```

## Verification

- Baseline and probe share a status class when the identifier is allowlisted; a 200/500 split is the signal.
- The benign value returns the full record set, proving the parameter is actually used.
- Repeat on a second sink class with its own probe; a single class clearing does not clear the handler.
