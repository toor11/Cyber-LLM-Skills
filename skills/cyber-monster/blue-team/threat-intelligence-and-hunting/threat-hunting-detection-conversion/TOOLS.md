# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-hunting-detection-conversion`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sigma` | `sigma convert -t splunk -p splunk_windows rules/88f1.yml` | Convert a portable rule to the target backend | Cross-platform |
| `sigma` | `sigma check rules/88f1.yml` | Validate structure and specification compliance | Cross-platform |
| `chainsaw` | `chainsaw hunt evtx/ --sigma rules/ --json` | Replay rules against captured event logs to test | Cross-platform |
| `git` | `git log -p -- rules/88f1.yml` | Tuning history and exception changes | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Rule readiness: validate, convert, then replay against captured events.
set -euo pipefail
rule=${1:?rule file}
sigma check "$rule"
sigma convert -t splunk -p splunk_windows "$rule" > converted.spl
printf '== replay against captured hunt events ==\n'
chainsaw hunt "${EVIDENCE_DIR:-evtx/}" --sigma "$rule" --json > replay.json || true
python - <<'PY'
import json
d = json.load(open("replay.json"))
hits = d if isinstance(d, list) else d.get("detections", [])
print("replay detections:", len(hits))
for h in hits[:5]:
    print(" ", h.get("name") or h.get("title"), h.get("path") or h.get("document", {}).get("path"))
PY
```

## Verification

- The replay produces at least one detection on the original hunt evidence; zero means the analytic was lost in conversion.
- `sigma check` passes, so the rule is structurally portable before it is tuned to one backend.
- Running the same replay over a benign capture produces zero, which is the baseline half of the differential.
