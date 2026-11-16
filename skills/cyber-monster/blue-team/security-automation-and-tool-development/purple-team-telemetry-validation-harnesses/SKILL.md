---
name: purple-team-telemetry-validation-harnesses
description: "Builds safe purple-team detection validation runners and ATT&CK Navigator layer generators: executing benign/reversible telemetry checks in lab hosts, polling SIEM/EDR APIs with correlation UUIDs to measure detection latency and field completeness, and exporting red/amber/green coverage JSON layers. Use when automating detection coverage verification."
family: security-automation-and-tool-development
tier: core
triggers: ["purple team harness", "telemetry validation script", "attack navigator json generator", "detection latency test"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Purple Team Telemetry Validation Harnesses - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A detection is only proven by an event that actually occurred, was actually collected, and was actually matched — three separable stages, and a coverage report that conflates them cannot tell you which one broke. The harness therefore works as a controlled experiment: execute a benign, reversible action on a lab host that should produce a specific observable; tag it with a unique correlation identifier that will appear in the telemetry; poll the SIEM or EDR query API until the identifier surfaces or a timeout expires; then record the measured latency, the fields present, and whether the expected rule fired. Each stage has its own failure signature. Nothing in the SIEM at all means collection or onboarding; the raw event present but no alert means the rule did not match; the alert present but missing a field means the detection is fragile even though it fired. Results map onto ATT&CK techniques and export as an ATT&CK Navigator layer — the current layer format is 4.5, with `versions.layer: "4.5"`, `domain` set to `enterprise-attack`/`mobile-attack`/`ics-attack`, and a `techniques[]` array of `{techniqueID, score, comment}`. The hard constraint is reversibility: every action must have a cleanup step that runs even on failure, and nothing destructive or persistence-establishing belongs in a validation harness.

- **CWE-778 (Insufficient Logging):** the harness exists to detect insufficient logging; a harness that reports "covered" from a rule existing in the repository reproduces the problem it is meant to catch.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you build a validation case **THEN** make the action benign and reversible, embed a unique correlation identifier in it, and register a `cleanup()` that runs on success and on failure.
2. **IF** you measure detection **THEN** poll for the identifier with a bounded timeout and record three outcomes separately: event collected, rule fired, fields complete.
3. **IF** you report coverage **THEN** emit an ATT&CK Navigator layer 4.5 (`versions.layer: "4.5"`, valid `domain`, `techniques[]` with `techniqueID` and `score`), and keep the per-case evidence beside it.
4. **IF** a case shows "event collected, no alert" **THEN** classify it as a detection gap, not a collection gap — the two need different remediation owners.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `purple-team-telemetry-validation-harnesses` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable harness and layer shapes | [`QUERIES.md`](QUERIES.md) | Case execution, polling, cleanup, Navigator layer JSON |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | Atomic tests, SIEM query clients, layer schema fields |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | False-coverage and missing-cleanup incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Lab-scope handoff if a test escapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** lab-scoped validation runner (Python 3.11) with a bounded poll loop over a SIEM/EDR query API, plus an ATT&CK Navigator layer 4.5 export
- **Mandatory Self-Validation Command:** `python -m py_compile purple_harness.py`

1. **Confirm the inputs.** Establish the lab hosts and their isolation, the SIEM/EDR query endpoint, the technique-to-case mapping, and the expected observable per case. Confirm every case has a cleanup path and that nothing in scope is production.
2. **Choose the branch.** Telemetry-only case → action plus identifier plus collection assertion. Detection case → adds the rule-fired assertion. Field-completeness case → adds the per-field assertion. Each branch produces a different verdict, and mixing them into one boolean loses the diagnostic value.
3. **Define how to validate the harness itself.** Run one case whose detection is known to exist and assert it reports collected + fired + complete; run one case with the rule disabled and assert it reports collected + not fired; assert cleanup ran in both, and assert the layer JSON validates against the 4.5 schema requirements.
4. **Name the stop condition.** Stop when cleanup fails (the environment is no longer in a known state), when the poll timeout expires without the identifier, when a case targets anything outside the lab, or when the layer export lacks a valid `versions.layer` and `domain`.
5. **State what counts as a working tool.** A working harness exits `0` when every case resolved in a definite state with cleanup confirmed, `1` when at least one case reported a coverage gap, and `2` when cleanup or environment validation failed. Its output pairs the Navigator layer with the per-case evidence rows.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Correlation identifier embedded in the action | Proves the event found in the SIEM is the one this case produced |
| Bounded poll loop with recorded latency | Proves the measurement is time-bounded and gives a defensible MTTD |
| Separate verdicts: collected / fired / fields | Proves which stage failed, so the gap has an owner |
| `cleanup()` invoked in a `finally` block | Proves the lab returns to a known state even on failure |
| `versions.layer: "4.5"` with a valid `domain` | Proves the layer is importable by the current Navigator |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: runs a real technique, waits a fixed time, declares coverage from
# the rule's presence in the repository, and leaves lab state behind.
import time

import requests

def validate(rule_id, host):
    requests.post(f"http://lab-host/{host}/run-technique", timeout=10)   # no cleanup, no correlation id
    time.sleep(300)                                                       # fixed wait
    rules = requests.get("http://siem/api/rules", timeout=10).json()
    return any(r["id"] == rule_id for r in rules)                         # rule exists, so "covered"
```

**Production-Grade Starter Skeleton (USE):**

```python
# purple_harness.py - Exit 0 all cases resolved with cleanup, 1 coverage gap, 2 cleanup/env failure
import datetime as dt
import json
import sys
import time
import uuid

CASES = [
    {"technique": "T1059.001", "name": "powershell_encoded_command",
     "expected_rule": "suspicious_powershell_encoded",
     "expected_fields": ("process.command_line", "process.parent.executable")},
    {"technique": "T1547.001", "name": "registry_run_key_write",
     "expected_rule": "registry_run_key_persistence",
     "expected_fields": ("registry.path", "registry.value")},
]

def poll_for(correlation_id: str, timeout_s: int = 300, interval_s: int = 15) -> tuple[dict | None, float | None]:
    started = time.monotonic()
    while time.monotonic() - started < timeout_s:
        event = query_telemetry(correlation_id)          # SIEM/EDR query implementation
        if event:
            return event, round(time.monotonic() - started, 1)
        time.sleep(interval_s)
    return None, None

def query_telemetry(correlation_id: str) -> dict | None:
    """Return the first telemetry document whose command line carries the correlation id."""
    return None

def run_case(case: dict) -> dict:
    correlation_id = f"pt-{case['name']}-{uuid.uuid4().hex[:12]}"
    started = dt.datetime.now(dt.timezone.utc)
    verdict = {"technique": case["technique"], "case": case["name"],
               "correlation_id": correlation_id, "collected": False,
               "fired": False, "fields_complete": False, "latency_s": None,
               "cleanup_ok": False, "started": started.isoformat()}
    try:
        execute_benign_action(case["name"], correlation_id)
        event, latency = poll_for(correlation_id)
        if event:
            verdict["collected"] = True
            verdict["latency_s"] = latency
            matched = (event.get("rule", {}).get("name") == case["expected_rule"])
            verdict["fired"] = matched
            verdict["fields_complete"] = all(
                resolve_field(event, path) is not None for path in case["expected_fields"]
            )
    finally:
        verdict["cleanup_ok"] = cleanup(case["name"], correlation_id)
    return verdict

def execute_benign_action(name: str, correlation_id: str) -> None:
    """Placeholder for the lab action: must be benign, reversible, and carry the id."""

def cleanup(name: str, correlation_id: str) -> bool:
    """Reverse the action and confirm the host is back to baseline."""
    return True

def resolve_field(document: dict, dotted: str):
    current = document
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current

def score(verdict: dict) -> int:
    if not verdict["collected"]:
        return 0
    if not verdict["fired"]:
        return 50
    return 100 if verdict["fields_complete"] else 75

def to_layer(verdicts: list[dict]) -> dict:
    return {
        "name": "Purple team validation",
        "versions": {"layer": "4.5", "navigator": "5.0.0", "attack": "15"},
        "domain": "enterprise-attack",
        "description": "Measured coverage from controlled telemetry validation",
        "techniques": [
            {"techniqueID": v["technique"], "score": score(v),
             "comment": f"collected={v['collected']} fired={v['fired']} fields={v['fields_complete']}"}
            for v in verdicts
        ],
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
    }

def main() -> int:
    verdicts = [run_case(case) for case in CASES]
    for verdict in verdicts:
        print(json.dumps(verdict, sort_keys=True))
    print(json.dumps({"layer": to_layer(verdicts)}, indent=2))
    if any(not v["cleanup_ok"] for v in verdicts):
        sys.stderr.write("cleanup failed: lab state unknown\n")
        return 2
    return 1 if any(score(v) < 100 for v in verdicts) else 0

if __name__ == "__main__":
    raise SystemExit(main())
```

**Why this matters:** each case yields three separable verdicts plus a measured latency, cleanup runs in a `finally` so a failed case cannot leave the lab dirty, and the export is a Navigator 4.5 layer whose scores are computed from measurements rather than from rule inventory.

## When It Is NOT This Issue

- **A case shows no telemetry at all** — collection or onboarding gap, not a detection gap; check the agent and the log source before touching rules.
- **Telemetry arrives but no alert** — the rule did not match; that is a detection gap with a different owner than a collection gap.
- **Alert fires but a field is empty** — the detection is functional but fragile; missing `process.parent.executable` breaks triage even though the rule matched.
- **Coverage looks complete while incidents are missed** — the harness is scoring rule existence rather than measured events; only an executed, correlated event proves coverage.
- **A case leaves lab state behind** — cleanup did not run on failure; the harness must treat that as a hard stop because the next run's baseline is now wrong.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER run a validation case outside an isolated lab, and never include a destructive or persistence-establishing action.
- NEVER report coverage from the presence of a rule; coverage requires an executed event observed in telemetry.
- NEVER omit cleanup or run it only on the success path.
- NEVER assert a Navigator layer version or field set without checking the current schema.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Lab isolation, query endpoint, technique mapping, and cleanup path for `purple-team-telemetry-validation-harnesses` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The case, poll loop, or layer export is specific and runnable (no generic 'test detections' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: purple-team-telemetry-validation-harnesses
- **Target Stack & Schema**: lab-scoped Python runner with bounded SIEM polling and ATT&CK Navigator layer 4.5 export
- **Safety, Scope & Exit-Code Guards**: [Lab-only, reversible actions, guaranteed cleanup, measured latency, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Collection vs detection gaps, incomplete fields, cleanup failure, rule-existence false coverage]
- **Implementation**:
  [Runnable harness following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile purple_harness.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md) - The rules this harness validates end to end
- [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) - Static coverage inventory; this skill supplies the measured half
- [`siem-query-transpiler-and-enrichment-scripting`](../siem-query-transpiler-and-enrichment-scripting/SKILL.md) - The query layer the poll loop uses
- [`cis-benchmark-and-baseline-compliance-scripting`](../cis-benchmark-and-baseline-compliance-scripting/SKILL.md) - Configuration controls validated the same way

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `purple-team-telemetry-validation-harnesses` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
