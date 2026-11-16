# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`yara-rule-authoring`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for compiling and scanning with YARA-X and for cross-checking against legacy YARA. Never invent flags — run `yr <command> --help`, because subcommands and options have changed repeatedly across the 1.x line.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `yr check` | `yr check rules/` | Lint rules under the stricter engine and its `.yara-x.toml` conventions; exits non-zero on errors | Cross-platform |
| `yr compile` | `yr compile --output rules.yarc rules/` | Produce a compiled rule set for repeated scanning without re-parsing | Cross-platform |
| `yr scan` (replay) | `yr scan --compiled-rules family.yarc --recursive /opt/artifacts` | Scan a tree with the precompiled set, recursively | Cross-platform |
| `yr scan` (output) | `yr scan --output-format ndjson --print-strings rules/family.yar sample.exe` | Machine-readable matches including which strings fired, for triage and diffing | Cross-platform |
| `yr scan` (limits) | `yr scan --threads 8 --timeout 120 rules/family.yar /data` | Bound CPU and wall time on a large scan target | Cross-platform |
| `yr fmt` / `yr fix` | `yr fmt rules/` and `yr fix rules/` | Normalise formatting and auto-repair fixable lint findings | Cross-platform |

## Minimal Script Shape

The shape below is the minimum defensible rule gate: lint, compile to a reusable set, then measure precision on a benign corpus and coverage on the positive set before declaring the rule ready.

```bash
#!/usr/bin/env bash
# yara-gate.sh — lint, compile, measure precision, then measure coverage.
set -euo pipefail

RULES="${RULES:-./rules/family.yar}"
BENIGN="${BENIGN:-/usr/bin}"
POSITIVE="${POSITIVE:-./samples/positive}"
MAX_BENIGN_HITS="${MAX_BENIGN_HITS:-0}"
OUT="$(mktemp -d)"

# 0. Lint and compile under the engine that will actually run the rule.
yr check "$RULES"
yr compile --output "${OUT}/family.yarc" "$RULES"

# 1. Precision gate: matches on a benign corpus must stay at or under the budget.
yr scan --compiled-rules "${OUT}/family.yarc" --recursive --output-format ndjson "$BENIGN" \
  > "${OUT}/benign.ndjson" || true
benign_files=$(jq -r '.path' "${OUT}/benign.ndjson" | sort -u | wc -l)
echo "benign_files_matched=${benign_files}"
if [ "$benign_files" -gt "$MAX_BENIGN_HITS" ]; then
  echo "FAIL: precision budget exceeded -> review matched strings with --print-strings"
  jq -r '.path' "${OUT}/benign.ndjson" | sort -u | head -20
  exit 2
fi

# 2. Coverage gate: every positive sample must match, with the string identifiers shown.
yr scan --compiled-rules "${OUT}/family.yarc" --recursive --print-strings \
  --output-format ndjson "$POSITIVE" > "${OUT}/pos.ndjson" || true
total=$(find "$POSITIVE" -type f | wc -l)
hit=$(jq -r '.path' "${OUT}/pos.ndjson" | sort -u | wc -l)
echo "positive_covered=${hit}/${total}"
jq -c '{path: .path, ids: [.rules[].identifier]}' "${OUT}/pos.ndjson"
```

## Notes That Prevent Wrong Runs

- `--recursive` without a depth bound will walk an entire filesystem; on a shared host, scope the target or bound it explicitly.
- `--compiled-rules` pairs with a `.yarc` produced by `yr compile`; using a source file with that flag fails rather than falling back.
- `--output-format json` emits one object at the end of the scan, while `ndjson` emits one per matching file. Streaming pipelines need `ndjson`.
- Legacy `yara` and `yr` do not share a compiled format. If the fleet runs both, deploy the source rules and compile per engine.
