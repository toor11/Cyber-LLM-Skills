---
name: sigma-pipeline-and-backend-development
description: "Builds Sigma detection-as-code toolchains with `pySigma` (never deprecated `sigmac`): custom `ProcessingPipeline` field/logsource transformations, KQL/SPL/ESQL backend compilation, metadata schema linters, and positive/benign EVTX/JSON CI regression test runners. Use when engineering Sigma rule compilation and CI validation pipelines."
family: security-automation-and-tool-development
tier: flagship
triggers: ["pysigma", "sigma pipeline python", "sigma backend compiler", "detection as code ci", "processingpipeline"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling, ocsf-and-ecs-log-normalizer-development]
---

# Sigma Pipeline and Backend Development - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **flagship** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)

## Mechanism and Preconditions

A Sigma rule is a portable detection document, not a query. `pySigma` parses that document into a `SigmaRule` object model, a `ProcessingPipeline` rewrites fields and logsource identity for one target environment, and a backend serialises the transformed rule into KQL, SPL, ES|QL, or Lucene. The pipeline is therefore the only place where site-specific field names belong; a rule that hardcodes an ECS field name has silently become vendor-locked. Compilation is deterministic, so it is testable: the same rule plus the same pipeline must always produce the same query text, and that text is what CI diffs, deploys, and regression-tests against retained telemetry. Correlation rules (`SigmaCorrelationRule`) are a separate object type that reference base rules by `name`/`id` and add `timespan`, `group-by`, and a `condition` threshold, so they are validated differently from detection rules.

- **CWE-778 (Insufficient Logging):** a compiled detection that never fires because its field mapping or logsource never matched is functionally missing logging.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you must emit a query for a specific SIEM **THEN** pin `pySigma` >= 1.5, install the backend plugin (`sigma plugin install splunk` / `elasticsearch`), and compile with `sigma convert -t <target> -p <pipeline> rules/`; never shell out to archived `sigmac`.
2. **IF** your environment renamed fields (ECS, OCSF-mapped, or a raw vendor schema) **THEN** express every rename as `ProcessingItem(identifier=..., transformation=FieldMappingTransformation({...}))` inside a named `ProcessingPipeline`, and chain pipelines through `ProcessingPipelineResolver.resolve()` so `priority` ordering is honoured instead of list order.
3. **IF** a rule set contains `correlation:` documents **THEN** load them with `SigmaCollection.load_ruleset([...])` and treat any `collection.errors` entry as a build failure; correlation rules carry no `logsource` and cannot be converted alone.
4. **IF** the request is really about writing the detection content rather than the compiler **THEN** hand off to [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) for rule/ logsource inventory, and to [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) for file-signature rules.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `sigma-pipeline-and-backend-development` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable CI query and compiled-query shapes | [`QUERIES.md`](QUERIES.md) | Positive/benign regression fixtures and backend output samples |
| Need CLI syntax, plugin install, and version pins | [`TOOLS.md`](TOOLS.md) | `sigma convert`, `sigma check`, backend-specific flags |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled pipeline failures from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** `pySigma` >= 1.5 (`sigma.collection.SigmaCollection`, `sigma.processing.pipeline.ProcessingPipeline`/`ProcessingItem`, `sigma.processing.pipeline.ProcessingPipelineResolver`, `sigma.correlations.SigmaCorrelationRule`, `sigma-cli` — never archived `sigmac`)
- **Mandatory Self-Validation Command:** `python -m py_compile sigma_pipeline_check.py; sigma check rules/`

1. **Confirm the inputs.** Establish which rule directories are in scope, which backend target and pipeline identifiers are installed (`sigma list targets`, `sigma list pipelines`), and which telemetry the compiled query will actually run against. Record the `pySigma` and plugin versions; a query is only reproducible with the compiler that produced it.
2. **Choose the branch.** Field renames plus logsource adaptation go in a pipeline; unsupported constructs (a modifier the backend cannot express) require either a backend capability check or an explicit `SigmaConversionError` path. If the only change is output formatting, use backend options, not a transformation.
3. **Define how to validate the script.** Three gates, in order: `python -m py_compile` for the harness itself; `sigma check rules/` for rule-schema and modifier legality; then your own fixture runner that compiles each rule and compares the emitted query against a committed golden file. A rule that compiles but produces an empty `condition` fails the third gate.
4. **Name the stop condition.** Stop when any rule raises `SigmaError`, when a compiled query text changes without a corresponding rule or pipeline change in the same commit, or when a positive fixture no longer matches while its benign twin starts matching. Do not paper over a conversion error by deleting the offending modifier.
5. **State what counts as a working tool.** A working pipeline exits `0` only when every rule compiled, every golden file matched, and the fixture differential held; exits `1` for rule/conversion findings; exits `2` for a missing plugin, unreadable rule path, or absent backend.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `sigma.collection.SigmaCollection.load_ruleset([...], collect_errors=True)` | Proves the whole rule tree parses as objects and exposes per-file `collection.errors` instead of one opaque YAML traceback |
| `sigma.processing.pipeline.ProcessingItem(identifier=..., transformation=FieldMappingTransformation({...}))` | Proves which fields the environment rename actually touches, so ECS/vendor drift is attributable to one pipeline item |
| `sigma.processing.pipeline.ProcessingPipelineResolver.resolve([...])` | Proves pipeline ordering came from `priority` values, not from the order the caller happened to concatenate them |
| `sigma.correlations.SigmaCorrelationRule` (`type`, `timespan`, `group-by`, `condition`) | Proves a threshold/temporal rule referenced real base rules and carries a valid aggregation, which plain rule linting cannot show |
| `sigma check rules/` exit status | Proves modifier/logsource legality against the installed spec version before any query reaches a SIEM |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```yaml
# ANTI-PATTERN: site field names baked into the rule, so the rule only works in one SIEM
title: Suspicious PowerShell Encoded Command
id: 7f3d1e2a-0000-4000-8000-000000000001
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    process.command_line|contains: '-enc'
  condition: selection
level: high
```

**Production-Grade Starter Skeleton (USE):**

```python
# sigma_pipeline_check.py - Exit 0 clean, 1 rule/conversion finding, 2 env or path error
import json
import pathlib
import sys

import yaml
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

ECS_WIN_PROCESS = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
}

def build_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="ecs_win_process_creation",
        priority=20,
        items=[
            ProcessingItem(
                identifier="ecs_process_fields",
                transformation=FieldMappingTransformation(ECS_WIN_PROCESS),
            )
        ],
    )

def check(rule_dir: pathlib.Path) -> int:
    if not rule_dir.is_dir():
        sys.stderr.write(f"fatal: not a rule directory: {rule_dir}\n")
        return 2
    collection = SigmaCollection.load_ruleset([rule_dir], collect_errors=True)
    failures = 0
    for error in collection.errors:
        failures += 1
        print(json.dumps({"stage": "parse", "error": str(error)}))
    pipeline = build_pipeline()
    for rule in collection.rules:
        missing = [field for field in ("id", "level") if getattr(rule, field, None) is None]
        if missing:
            failures += 1
            print(json.dumps({"stage": "metadata", "rule": rule.title, "missing": missing}))
            continue
        pipeline.apply(rule)
        if not rule.detection.parsed_condition:
            failures += 1
            print(json.dumps({"stage": "condition", "id": str(rule.id)}))
    return 1 if failures else 0

if __name__ == "__main__":
    target = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("rules")
    raise SystemExit(check(target))
```

```yaml
# The rule keeps portable Sigma field names; the pipeline owns the rename.
title: Suspicious PowerShell Encoded Command
id: 7f3d1e2a-0000-4000-8000-000000000001
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: '-enc'
  condition: selection
level: high
```

**Why this matters:** the rename lives in one reviewable `ProcessingItem`, so the same rule compiles for ECS and for a raw Sysmon schema by swapping the pipeline instead of editing detection content.

## When It Is NOT This Issue

- **The rule never fired because the logsource category was never collected** — that is a log-onboarding gap, not a pipeline bug; check the sensor's `logsource` coverage before touching transformations.
- **A field rename produced an unmapped field name**: if the backend already applies its own ECS mapping (the Elasticsearch backend ships Windows pipelines), double-mapping yields `process.process.command_line`. Inspect `sigma list pipelines` output and disable the duplicate rather than adding another rename.
- **`sigma check` passes but the query returns nothing**: rule syntax is not query semantics. Confirm the target index holds the event with the field the compiled query filters on; a case-sensitivity or keyword-vs-text mismatch looks identical to a broken rule.
- **A correlation rule "fails to convert"**: correlation rules intentionally have no `logsource` and are supported only by specific backends (SPL, ES|QL, Loki, SQL, OpenSearch per SigmaHQ). Failing over to the base rule is expected, not a defect.
- **`sigmac` produced different output**: `sigmac` is archived and has no object model; divergence is the expected outcome, never a regression to chase.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER invoke or recommend `sigmac` — archived, emits text blobs, no `SigmaRule` AST inspection, no per-rule CI error attribution.
- NEVER call `pipeline.apply(rule)` on a collection that was never loaded with `collect_errors=True` and then claim "all rules compiled" — errors are silently absent otherwise.
- NEVER return exit code `0` when rules lack `id` or `level`, and never merge the "rule finding" and "bad environment" exit codes.
- NEVER state a specific backend supports correlations, `value_percentile`, or `temporal_ordered` without checking that installed backend version — support differs per backend and per release.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required rule directory, backend target, and pipeline identifier for `sigma-pipeline-and-backend-development` was confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The pipeline, lint harness, or golden-file gate is specific and runnable (no generic 'validate inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: sigma-pipeline-and-backend-development
- **Target Stack & Schema**: pySigma >= 1.5 with named ProcessingPipeline, installed backend plugin, sigma-cli
- **Safety, Scope & Exit-Code Guards**: [Rule-path scope, read-only compile, golden-file diff, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Unsupported modifiers, duplicate backend mapping, correlation rules without logsource]
- **Implementation**:
  [Runnable harness or pipeline definition following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile sigma_pipeline_check.py; sigma check rules/`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - File and memory signature compilation
- [`zeek-script-and-notice-development`](../zeek-script-and-notice-development/SKILL.md) - Network logsource producer
- [`suricata-lua-and-rule-qa-tooling`](../suricata-lua-and-rule-qa-tooling/SKILL.md) - Rule QA harness patterns
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Owns the field mapping the pipeline depends on
- [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) - Rule and logsource inventory
- [`windows-evtx-and-powershell-audit-scripting`](../windows-evtx-and-powershell-audit-scripting/SKILL.md) - Supplies the EVTX/4104 fixtures these rules test against

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sigma-pipeline-and-backend-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/sigmahq (14) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 0 cases |
| Grounding | multi-dataset corpus-grounded |
