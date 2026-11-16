# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`remediation-tracking-and-verification`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `openssl` | `openssl s_client -connect lb:443 -tls1` | Configuration probe for a TLS finding | Cross-platform |
| `dpkg`/`rpm` | `dpkg -l openssl` | Asset-reported version for a patch finding | Linux |
| `semgrep` | `semgrep scan --config p/owasp-top-ten --error path/to/fixed` | Code probe against the fixed commit | Cross-platform |
| `jq` | `jq 'select(.status=="closed")' items.json` then inspect each item's `probe.captured` field | Find closures missing their probe artefact | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json

items = json.load(open("remediation.json"))
bad = []
for it in items:
    if it["status"].startswith("closed"):
        if not it.get("probe", {}).get("captured"):
            bad.append((it["id"], "closed without probe artefact"))
        elif it["probe"].get("result") == it.get("baseline_evidence"):
            bad.append((it["id"], "probe result unchanged from baseline"))
    elif it.get("due") and it["due"] < "2026-11-14":
        bad.append((it["id"], "open past due date"))

print("items:", len(items), "problems:", len(bad))
for b in bad[:10]:
    print(" ", b)
raise SystemExit(0 if not bad else 1)
```

## Verification

- A closed item missing its probe artefact fails, which enforces the class-specific closure rule.
- A probe whose result equals the baseline is flagged, catching 're-ran and it looks the same' closures.
- Open overdue items appear in the same output, so ageing is visible rather than reported separately.
