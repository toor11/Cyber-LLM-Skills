# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`detection-engineering`](SKILL.md) | Family: **Detection and Monitoring**

The working toolchain for authoring, converting, and checking detections. Flags below are current for `sigma-cli`; confirm against the installed version with `sigma --help` and `sigma convert --help` before wiring anything into a pipeline.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sigma-cli` | `sigma check rules/` | Lint structure and conventions before review | Cross-platform |
| `sigma-cli` | `sigma list targets` and `sigma list pipelines` | Enumerate backend and pipeline identifiers the version supports | Cross-platform |
| `sigma-cli` | `sigma convert -t splunk -p splunk_windows rules/ > build/queries.spl` | Produce the deployable query for one backend | Cross-platform |
| `sigma-cli` | `sigma convert -t sentinel -p sentinel_windows rules/rule.yml` | Same source, different backend, so the diff can be reviewed | Cross-platform |
| `pySigma` | `python -c "from sigma.collection import SigmaCollection; c=SigmaCollection.from_yaml(open('r.yml').read()); print(len(c.rules))"` | Parse a rule programmatically to assert metadata and condition shape in tests | Python 3.10+ |
| Sysmon config dump | `sysmon64 -c` | Print the effective config, including which event IDs are included, before claiming an event exists | Windows |
| Splunk `btool` | `btool props list` and `btool transforms list` | Confirm the sourcetype actually extracts the fields the rule reads | Search head or indexer |
| Velociraptor VQL | `SELECT *, event_data.EventID FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Security.evtx") WHERE event_data.EventID = 4688 LIMIT 5` | Verify a channel carries the artifact on a specific host without waiting for the SIEM | Windows, Linux, macOS |

## Minimal Script Shape

The script builds the claim's evidence in order: visibility, compilation, then the positive/negative pair.

```bash
#!/usr/bin/env bash
# author-check.sh — prove visibility, then compile, then exercise the fixture pair.
set -euo pipefail

RULE="${RULE:?set RULE to a rule path}"
BACKEND="${BACKEND:-splunk}"
PIPELINE="${PIPELINE:-splunk_windows}"
FIXTURES="${FIXTURES:-tests/fixtures}"

# 1. Structural lint.
sigma check "$RULE"

# 2. Compile. Refuse to continue on empty output, which some backends emit silently.
COMPILED=$(sigma convert -t "$BACKEND" -p "$PIPELINE" "$RULE")
if [ -z "${COMPILED//[[:space:]]/}" ]; then
  echo "COMPILE EMPTY for backend ${BACKEND}: logsource may be unsupported"; exit 3
fi
printf '%s\n' "$COMPILED" > "build/$(basename "${RULE%.yml}").${BACKEND}.txt"

# 3. Fixture pair must exist before the rule is called tested.
STEM=$(basename "${RULE%.yml}")
for kind in positive negative; do
  if [ ! -f "${FIXTURES}/${STEM}.${kind}.json" ]; then
    echo "FIXTURE GAP: ${STEM}.${kind}.json missing"; exit 4
  fi
done

# 4. Print the claim's evidence summary for the review record.
cat <<EOF
rule=$STEM backend=$BACKEND pipeline=$PIPELINE
compiled_bytes=$(wc -c < "build/${STEM}.${BACKEND}.txt")
fixtures=positive,negative
next: run the positive and negative fixtures, then sample one week of production alerts
EOF
```

## Notes That Prevent Wrong Runs

- Pin the pipeline identifier alongside the backend; a pipeline change alters modifier behaviour and therefore what the query matches.
- Treat empty compile output as a failure. Several logsource and backend pairs convert to nothing without a non-zero exit code.
- Verify field extraction with the platform's own introspection (`btool` on Splunk, the index's mappings API on Elastic) rather than assuming a field name from the rule compiles into a working reference.
- Keep the fixture pair in the repository with the rule; a fixture held in someone's notebook is not a test.
- Record the mapping target beside the rule: strategy, analytic, platform, depth. It is the only way to answer "what changed when the framework version moved".
