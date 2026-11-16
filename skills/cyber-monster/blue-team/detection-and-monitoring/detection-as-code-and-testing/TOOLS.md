# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`detection-as-code-and-testing`](SKILL.md) | Family: **Detection and Monitoring**

The toolchain for linting, compiling, testing, and deploying detection content. Never invent flags — run `sigma --help` and `sigma convert --help` on the installed version, because pySigma backend and pipeline names change between minor releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sigma-cli` | `sigma check rules/` | Lint rule structure and conventions as a required PR stage | Cross-platform |
| `sigma-cli` | `sigma list targets` and `sigma list pipelines` | Enumerate the backend and pipeline names the installed version actually offers | Cross-platform |
| `sigma-cli` | `sigma convert -t sentinel -p sentinel_windows rules/ > build/sentinel/queries.txt` | Compile for one backend and preserve the output as a build artefact | Cross-platform |
| `pySigma` | `python - <<'PY'` loading `SigmaCollection.from_yaml` and iterating `collection.rules` | Assert rule metadata, condition shape, and correlation type in a unit test | Python 3.10+ |
| `git` | `git diff --name-only origin/main...HEAD -- rules/` | Scope the pipeline to changed rules so the replay stage runs on what moved | Any host with the repo |
| GitHub Actions | `uses: actions/upload-artifact@v4` with `path: build/` | Attach the compiled queries to the commit for review and later drift comparison | CI |
| Splunk REST | `curl -k -u $AUTH https://$SH:8089/servicesNS/-/-/saved/searches?output_mode=json` | Fetch deployed saved-search text to compare against the built artefact | Search head |
| Microsoft Sentinel API | `curl -sS -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01"` | Enumerate deployed analytics rules for drift comparison | Cross-platform |

## Minimal Script Shape

The script enforces the three gates that matter: every declared backend compiles, every rule has a usable fixture pair, and no negative fixture fires.

```bash
#!/usr/bin/env bash
# detection-gate.sh — compile, fixture-audit, and replay before any promotion.
set -euo pipefail

RULES="${RULES:-rules}"
FIXTURES="${FIXTURES:-tests/fixtures}"
BACKENDS="${BACKENDS:-splunk sentinel elasticsearch}"
PIPELINE="${PIPELINE:-}"

# 1. Lint every rule in the repository.
sigma check "$RULES"

# 2. Compile for every declared backend; any failure aborts the build.
mkdir -p build
for backend in $BACKENDS; do
  sigma convert -t "$backend" ${PIPELINE:+-p "$PIPELINE"} "$RULES" > "build/${backend}.txt"
  test -s "build/${backend}.txt" || { echo "EMPTY COMPILE: $backend"; exit 3; }
done

# 3. Fixture audit: each rule needs a positive and a negative fixture on disk.
python3 - "$RULES" "$FIXTURES" <<'PY'
import os, sys, glob
rules_dir, fixture_dir = sys.argv[1], sys.argv[2]
missing = []
for rule in glob.glob(os.path.join(rules_dir, "**", "*.yml"), recursive=True):
    stem = os.path.splitext(os.path.basename(rule))[0]
    for kind in ("positive", "negative"):
        if not os.path.exists(os.path.join(fixture_dir, f"{stem}.{kind}.json")):
            missing.append(f"{stem}:{kind}")
if missing:
    sys.exit("FIXTURE GAP: " + ", ".join(missing))
print(f"fixture audit OK for {len(glob.glob(os.path.join(rules_dir, '**', '*.yml'), recursive=True))} rules")
PY

# 4. Replay fixtures; the harness must exit non-zero when a negative fires.
python3 tests/replay_fixtures.py \
  --compiled build/ --fixtures "$FIXTURES" --fail-on-negative-hit
```

## Notes That Prevent Wrong Runs

- Pin the pipeline name in the repository and reuse the identical value in production. A pipeline difference is an invisible query difference.
- Treat an empty compile output as a failure. Some backends exit zero while emitting nothing for an unsupported logsource.
- Keep fixtures in the target event schema, not in a hand-written approximation; a fixture that cannot parse silently stops testing the rule.
- Stamp `github.sha` or the equivalent into the deployed rule description. Without it the drift check has nothing to compare against.
- The replay harness must be able to fail. A harness whose exit code is ignored by the workflow turns every gate above into decoration.
