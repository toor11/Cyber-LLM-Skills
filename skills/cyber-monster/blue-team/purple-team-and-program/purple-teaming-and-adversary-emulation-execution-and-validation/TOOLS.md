# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`purple-teaming-and-adversary-emulation-execution-and-validation`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `invoke-atomicredteam` | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | Emulation with a known test number for reproducibility | Windows |
| `siem` | query the analytic's underlying event with a bounded time range | Event capture and analytic trace | Cross-platform |
| `jq` | `jq 'select(.technique=="T1053.005")' outcomes.json` | Outcome rollup across the exercise | Cross-platform |
| `git` | `git log -p -- detections/A-305.yml` | Show the filter change that closes the gap | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Bounded emulation with baseline and probe capture.
set -euo pipefail
tech=${1:?technique}; host=${2:?host}
base_from=$(date -u -d '24 hours ago' +%FT%TZ); base_to=$(date -u +%FT%TZ)
printf 'baseline %s..%s on %s\n' "$base_from" "$base_to" "$host" | tee -a result.txt
# replace with your platform's query; the point is the bounded window and captured output
siem query --host "$host" --from "$base_from" --to "$base_to" --json > baseline.json
start=$(date -u +%FT%TZ)
Invoke-AtomicTest "$tech" -TestNumbers 1 >/dev/null 2>&1 || true
end=$(date -u +%FT%TZ); sleep 120
siem alerts --host "$host" --from "$start" --to "$(date -u +%FT%TZ)" --json > alerts.json
printf 'probe %s..%s\n' "$start" "$end" >> result.txt
python -c "import json;b=json.load(open('baseline.json'));a=json.load(open('alerts.json'));print('baseline events',len(b),'alerts',len(a))"
```

## Verification

- The baseline count is printed before the emulation output, so attribution has a reference point.
- The alert query is bounded to the probe window, which excludes unrelated activity.
- Re-running the same script after the rule change shows a non-zero alert count, proving the fix.
