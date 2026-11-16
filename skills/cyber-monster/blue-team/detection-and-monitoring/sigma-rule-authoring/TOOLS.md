# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`sigma-rule-authoring`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for validating, converting and replaying Sigma rules. Never invent flags or pipeline names — run `sigma list pipelines` against the installed version, because backends and pipeline identifiers are separate packages and change independently of the core specification.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sigma check` | `sigma check rules/` | Validate YAML structure, spec conformance and required metadata; exits non-zero on parse errors by default | Cross-platform |
| `sigma check` (issues) | `sigma check --fail-on-issues -c validators.yml rules/` | Fail the build on quality findings, with an explicit validator selection | Cross-platform |
| `sigma list` | `sigma list targets` and `sigma list pipelines` | Enumerate what this installation can actually convert to, before writing a rule for a backend it cannot serve | Cross-platform |
| `sigma convert` | `sigma convert -t splunk -p splunk_windows rules/rule.yml` | Produce backend query text for review and deployment | Cross-platform |
| `sigma convert` (skip) | `sigma convert -t sentinel -p microsoft_xdr --skip-unsupported rules/rule.yml` | Convert while explicitly acknowledging unsupported constructs | Cross-platform |
| pySigma in-process | `SigmaCollection.from_yaml(path)` then `collection.transform(pipeline)` and `backend.convert()` | Programmatic validation in CI with the pipeline object you control | Cross-platform (Python 3) |
| `yamllint` | `yamllint -d relaxed rules/` | Catch indentation and duplicate-key defects that Sigma parsing may tolerate | Cross-platform |

## Minimal Script Shape

The shape below is the minimum defensible rule gate: validate, prove the logsource maps for the target backend, then convert without silently skipping unsupported constructs.

```bash
#!/usr/bin/env bash
# sigma-gate.sh — validate, prove mapping, convert without silent skips.
set -euo pipefail

RULES="${RULES:-./rules}"
TARGET="${TARGET:-splunk}"
PIPELINE="${PIPELINE:-splunk_windows}"

# 0. Does this installation even support the pair we intend to use?
sigma list targets | grep -qx "$TARGET" \
  || { echo "GAP: target '$TARGET' not installed"; exit 2; }
sigma list pipelines | grep -q "$PIPELINE" \
  || { echo "GAP: pipeline '$PIPELINE' not installed"; exit 2; }

# 1. Spec validity.
sigma check "$RULES"

# 2. Mapping proof: a probe rule must convert into something naming a real source.
PROBE="$(mktemp --suffix=.yml)"
cat > "$PROBE" <<'YAML'
title: Pipeline Probe
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\probe.exe'
  condition: sel
YAML
CONVERTED="$(sigma convert -t "$TARGET" -p "$PIPELINE" "$PROBE")"
printf '%s\n' "$CONVERTED"
printf '%s' "$CONVERTED" | grep -qi 'unknown\|placeholder\|<logsource>' \
  && { echo "GAP: $PIPELINE does not map process_creation"; exit 3; } || true

# 3. Convert the corpus, reporting anything the backend cannot express.
sigma convert -t "$TARGET" -p "$PIPELINE" "$RULES" > /tmp/rules_converted.txt
wc -l /tmp/rules_converted.txt
```

## Notes That Prevent Wrong Runs

- `sigma check` validates structure and spec conformance; it does not prove the backend pipeline maps the logsource. Those are two gates and both are required.
- `--skip-unsupported` converts what it can and drops the rest, so the output looks complete while coverage silently shrank. Use it only with a recorded count of what was skipped.
- pySigma 2.x moved policy handling to a dedicated module; a pipeline written for 1.x may need a `default_policy` adjustment rather than failing loudly.
- A multi-document rule file must keep the meta fields on the outermost correlation document; confirm both documents appear in the converted output rather than assuming conversion succeeded for the pair.
