---
name: detection-coverage-and-mitre-gap-analyzer-scripting
description: "Writes automated detection-catalog gap analyzers in Python: parsing Sigma/SIEM rule repositories, cross-referencing onboarded log sources (`datasources.yaml`) against threat-profile parent ATT&CK techniques, and flagging rules whose required log source is disabled or unmapped. Use when auditing SOC detection coverage programmatically."
family: security-automation-and-tool-development
tier: leaf
triggers: ["detection gap script", "sigma coverage analyzer", "logsource coverage python", "mitre matrix script"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Detection Coverage and MITRE Gap Analyzer Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **leaf** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Coverage analysis is a join between four lists that are each incomplete in different ways: the rules that exist, the log sources those rules require, the log sources the estate actually collects and forwards, and the techniques a threat profile says matter. The value is in the mismatches, and each mismatch has a different remedy. A rule whose `logsource` maps to nothing in the datasource inventory is dead content that inflates a coverage number. A rule whose log source is collected but disabled at the sensor is dead for an operational reason. A technique with no rule at all is a real gap. A technique covered only by rules on dead log sources is the most dangerous case, because a naive count reports it as covered. The ATT&CK side needs care too: techniques have parent/child relationships, and rolling sub-technique coverage up to a parent without saying so overstates the parent, while counting a parent as covered because one child is covered hides the rest. The output is therefore a matrix with evidence per cell — technique, contributing rules, log sources required, log sources present, and the resulting verdict — not a single percentage.

- **CWE-778 (Insufficient Logging):** a coverage number derived from rule inventory rather than from collected telemetry describes intent, not visibility.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you parse Sigma rules **THEN** read each rule's `logsource` (`product`/`category`/`service`) and its ATT&CK tags, and treat a rule with no resolvable log source as not counted toward coverage.
2. **IF** you compare against the estate **THEN** join on a normalized log-source key against the datasource inventory, and distinguish "not configured" from "configured but disabled".
3. **IF** you roll up techniques **THEN** report parent and sub-technique coverage separately and state the rollup rule; never let one covered child imply the parent.
4. **IF** you publish a coverage number **THEN** attach the per-technique evidence that produced it, so a disputed figure can be traced to specific rules and sources.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `detection-coverage-and-mitre-gap-analyzer-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable analyzer shapes | [`QUERIES.md`](QUERIES.md) | Rule parsing, logsource join, parent/child rollup, evidence rows |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `pySigma`, YAML parsing, datasource inventory formats |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Inflated-coverage and rollup incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Gap-remediation handoff |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11 analyzer over Sigma rule YAML (`logsource`, `tags` with `attack.tNNNN[.NNN]`) joined against a datasource inventory and an ATT&CK technique list, with per-technique evidence output
- **Mandatory Self-Validation Command:** `python -m py_compile coverage_gap.py`

1. **Confirm the inputs.** Establish the rule repository path, the inventory format and how a log source is identified there, the ATT&CK domain and version, and the threat profile that defines which techniques matter. Confirm the inventory reflects what is forwarded, not what is theoretically installable.
2. **Choose the branch.** Rule-health audit → rules joined to sources, reporting dead content. Technique coverage → techniques joined to contributing rules. Threat-profile gap → the profile's techniques intersected with the covered set. Each produces a different report and a different remediation owner.
3. **Define how to validate the analyzer.** Assert that a rule with a known-absent log source is reported as dead; assert that a rule with a present source is counted; assert that a technique covered only by a dead-source rule is reported as uncovered rather than covered; and assert the parent/child rollup respects the declared rule with a fixture where only one child is covered.
4. **Name the stop condition.** Stop when a rule's log source cannot be normalized to an inventory key, when the ATT&CK version is unknown (tag interpretation changes), when a coverage figure cannot be traced to evidence rows, or when the inventory's timestamp predates the last sensor change.
5. **State what counts as a working tool.** A working analyzer exits `0` when it produced a complete matrix with evidence, `1` when it found gaps (if used as a gate), and `2` on an unreadable repository or missing inventory. Every cell names the rules and sources behind it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Rule `logsource` normalized to an inventory key | Proves the join is on a real source identifier, not a guess |
| `attack.tNNNN.NNN` tags mapped to techniques | Proves technique attribution comes from the rule's own metadata |
| "configured but disabled" as a distinct state | Proves an operational gap is not reported as a content gap |
| Parent coverage requiring its own evidence | Proves a single covered child does not stand in for the parent |
| Per-technique evidence rows | Proves a coverage percentage can be traced to specific rules |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: counts rules per technique tag, ignores whether the log source is
# collected, and lets one sub-technique imply its parent.
import collections
import pathlib

import yaml

def coverage(rule_dir):
    counts = collections.Counter()
    for path in rule_dir.rglob("*.yml"):
        doc = yaml.safe_load(path.read_text())
        for tag in doc.get("tags", []):
            if tag.startswith("attack.t"):
                counts[tag[7:].upper()] += 1
    return {tech: 100 for tech, n in counts.items() if n}
```

**Production-Grade Starter Skeleton (USE):**

```python
# coverage_gap.py - Join rules to collected log sources and report per-technique evidence.
# Exit 0 matrix produced, 1 gaps found, 2 unreadable input.
import collections
import json
import pathlib
import re
import sys

import yaml

TAG_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)

def logsource_key(logsource: dict) -> str:
    parts = [str(logsource.get(k, "")).lower() for k in ("product", "service", "category")]
    return "|".join(p for p in parts if p)

def load_inventory(path: pathlib.Path) -> dict[str, str]:
    """Map a normalized logsource key to 'enabled' or 'disabled'."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = {}
    for entry in doc.get("sources", []):
        key = logsource_key(entry)
        out[key] = "enabled" if entry.get("enabled", True) else "disabled"
    return out

def load_rules(rule_dir: pathlib.Path) -> list[dict]:
    rules = []
    for path in sorted(rule_dir.rglob("*.yml")) + sorted(rule_dir.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        techniques = []
        for tag in doc.get("tags", []) or []:
            m = TAG_RE.match(str(tag))
            if m:
                techniques.append(f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else ""))
        rules.append({
            "path": str(path),
            "title": doc.get("title", path.stem),
            "logsource": logsource_key(doc.get("logsource") or {}),
            "techniques": techniques,
        })
    return rules

def analyze(rules: list[dict], inventory: dict[str, str], profile: list[str]) -> dict:
    by_technique = collections.defaultdict(lambda: {"live": [], "dead": [], "disabled": []})
    dead_rules = []
    for rule in rules:
        state = inventory.get(rule["logsource"])
        if state is None:
            dead_rules.append({"title": rule["title"], "logsource": rule["logsource"],
                               "reason": "not_collected"})
            bucket = "dead"
        elif state == "disabled":
            dead_rules.append({"title": rule["title"], "logsource": rule["logsource"],
                               "reason": "collected_but_disabled"})
            bucket = "disabled"
        else:
            bucket = "live"
        for technique in rule["techniques"]:
            by_technique[technique][bucket].append(rule["title"])
    matrix = []
    for technique in sorted(set(profile) | set(by_technique)):
        entry = by_technique.get(technique, {"live": [], "dead": [], "disabled": []})
        if entry["live"]:
            verdict = "covered"
        elif entry["disabled"]:
            verdict = "operational_gap"
        elif entry["dead"]:
            verdict = "content_gap"
        else:
            verdict = "no_detection"
        matrix.append({"technique": technique, "verdict": verdict,
                       "live_rules": entry["live"], "disabled_rules": entry["disabled"],
                       "dead_rules": entry["dead"]})
    parents = {}
    for row in matrix:
        if "." in row["technique"]:
            parent = row["technique"].split(".")[0]
            parents.setdefault(parent, []).append(row["verdict"])
    rolled = {p: ("covered" if "covered" in v else "gap") for p, v in parents.items()}
    return {"matrix": matrix, "dead_rules": dead_rules,
            "parent_rollup": rolled,
            "note": "parent rollup is informational; it does not substitute for per-sub-technique coverage"}

def main(argv: list[str]) -> int:
    if len(argv) < 3:
        sys.stderr.write("usage: coverage_gap.py <rule_dir> <datasources.yaml> [profile.json]\n")
        return 2
    rule_dir, inventory_path = pathlib.Path(argv[1]), pathlib.Path(argv[2])
    if not rule_dir.is_dir() or not inventory_path.is_file():
        sys.stderr.write("fatal: rule directory or inventory missing\n")
        return 2
    profile = []
    if len(argv) > 3:
        profile = json.loads(pathlib.Path(argv[3]).read_text(encoding="utf-8")).get("techniques", [])
    rules = load_rules(rule_dir)
    if not rules:
        sys.stderr.write("fatal: no rules parsed\n")
        return 2
    report = analyze(rules, load_inventory(inventory_path), profile)
    print(json.dumps(report, indent=2))
    gaps = [row for row in report["matrix"] if row["verdict"] != "covered"]
    return 1 if gaps else 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

**Why this matters:** a rule only counts when its log source is both present and enabled, so dead content cannot inflate the number, and the parent rollup is emitted separately with an explicit note that it is informational rather than a substitute for sub-technique evidence.

## When It Is NOT This Issue

- **Coverage looks complete but incidents are missed** — the analyzer counts rules whose log source is enabled, not events actually observed; pair it with measured validation.
- **A technique shows covered by a single rule with a narrow condition** — coverage here means "a detection exists", not "the technique is reliably caught"; the matrix must be read with rule quality in mind.
- **A log source is listed as collected but disabled at the sensor** — that is an operational gap with a different owner than a missing rule, and it is why the disabled state is separate.
- **A parent technique looks covered because one sub-technique is** — the rollup is informational; the per-child rows are the record.
- **Coverage drops after a rule cleanup** — removing duplicate or dead rules lowers the count while improving the program; the delta is expected.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER present a rule count as a coverage measurement without the log-source join.
- NEVER let a covered sub-technique stand in for its parent without stating the rollup rule.
- NEVER invent a log-source key; normalize from the rule's `logsource` fields and the inventory's own identifiers.
- NEVER assert an ATT&CK technique name or sub-technique relationship from memory; use the current ATT&CK version's data.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Rule repository, inventory format/freshness, ATT&CK version, and threat profile for `detection-coverage-and-mitre-gap-analyzer-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The join, rollup, or evidence output is specific and runnable (no generic 'measure coverage' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: detection-coverage-and-mitre-gap-analyzer-scripting
- **Target Stack & Schema**: Python analyzer over Sigma rule YAML joined to a datasource inventory and ATT&CK technique list
- **Safety, Scope & Exit-Code Guards**: [Read-only analysis, log-source join required, separate disabled state, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Dead content, disabled sources, parent/child rollup, rule-quality caveats]
- **Implementation**:
  [Runnable analyzer following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile coverage_gap.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md) - Provides the rule corpus this analyzer reads
- [`purple-team-telemetry-validation-harnesses`](../purple-team-telemetry-validation-harnesses/SKILL.md) - Supplies the measured half of coverage
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Determines whether a field the rule needs is actually populated
- [`waf-and-modsecurity-crs-rule-engineering`](../waf-and-modsecurity-crs-rule-engineering/SKILL.md) - Application-layer detections with the same dead-content risk

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `detection-coverage-and-mitre-gap-analyzer-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
