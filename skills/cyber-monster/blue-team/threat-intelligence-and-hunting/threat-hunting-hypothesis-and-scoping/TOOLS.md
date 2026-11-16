# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-hunting-hypothesis-and-scoping`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `siem` coverage query | a metadata query listing reporting hosts for the index, such as `index=win` with a host metadata lookup | Per-host coverage for the target event | Cross-platform |
| `jq` | `jq -r '.host' events.jsonl` piped to `sort -u` | Compare reporting hosts against the inventory list | Cross-platform |
| `osquery` | `osqueryi "SELECT hostname FROM system_info;"` | Endpoint confirmation for gap hosts | Cross-platform |
| `git` | `git log -1 -- scope/` | Bind the scope record to a revision | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Scope verification: population, coverage, and retention for the hunt window.
set -uo pipefail
cut -d, -f1 inventory-2026-11-13.csv | tail -n +2 | sort -u > population.txt
jq -r '.host' events.jsonl | sort -u > reporting.txt
printf 'population: '; wc -l < population.txt
printf 'reporting:  '; wc -l < reporting.txt
printf 'gaps:\n'; comm -23 population.txt reporting.txt | head -20
printf 'gap count: '; comm -23 population.txt reporting.txt | wc -l
printf 'oldest event: '; jq -r '.utc_time' events.jsonl | sort | head -1
```

## Verification

- The gap count is reported rather than hidden, and those hosts are excluded from any clean conclusion.
- The oldest event date is compared against the window start before the hunt is declared answerable.
- Re-running after enrolling a gap host reduces the gap count, proving the coverage view is live.
