---
name: yara-and-yara-x-scanner-engineering
description: "Develops high-throughput YARA and `yara-x` scanning pipelines in Python/Rust: `pe`/`elf`/`math` module rules, atom/loop performance profiling to prevent regex catastrophic slowdown, compiled ruleset caching, and automated false-positive benchmarking against clean-ware corpora. Use when building file/memory signature scanners or YARA QA gates."
family: security-automation-and-tool-development
tier: core
triggers: ["yara-python", "yara-x scanner", "yara performance lint", "yara ci pipeline"]
cwe: [CWE-400]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling, ocsf-and-ecs-log-normalizer-development]
corpus_sparse: true
---

# YARA and YARA-X Scanner Engineering - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A YARA rule is compiled into an atom set plus a condition automaton: the compiler extracts short byte sequences ("atoms") from each string, the scanner scans the target for those atoms, and only then evaluates the boolean condition. Everything that makes a rule slow lives in that first stage — too many atoms, atoms that are too generic (`{ 00 00 }`), or regular expressions that force a single-byte atom. YARA-X (the Rust rewrite, CLI `yr`, Python module `yara_x`) enforces stricter regex syntax than classic YARA and rejects rules whose atoms would be unusable, which turns a class of runtime slowdowns into compile-time errors. Its Python API is not compatible with `yara-python`, so a scanner written against `yara.compile`/`rules.match` must be rewritten rather than re-pointed. Throughput therefore comes from three levers: compiling once and reusing the compiled `Rules` object, rejecting pathological rules at CI time, and scanning with a bounded timeout per target so one crafted file cannot stall the fleet.

- **CWE-400 (Uncontrolled Resource Consumption):** a rule with a costly regular expression, or a scanner that loads whole files into memory, lets an attacker-chosen input consume the scanner's CPU or RAM.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are writing a new scanner **THEN** target `yara-x` (Python >= 3.9, `pip install yara-x`) with `yara_x.Compiler()` → `new_namespace()` → `add_source()` → `build()`, then `yara_x.Scanner(rules)`; call `set_timeout()` and `max_matches_per_pattern()` before scanning.
2. **IF** you must scan live process memory **THEN** stay on classic `yara-python`, because the YARA-X Python bindings do not expose process-memory scanning; document that split in the tool's README instead of silently mixing APIs.
3. **IF** a rule is slow under `yr scan --profiling` **THEN** fix the atoms (widen alternations, anchor strings, add `fullword`/`wide`, move expensive regexes behind a cheap `filesize` or `pe.*` guard) rather than raising the timeout.
4. **IF** the work is rule QA in CI **THEN** run `yr compile` over the rule tree and fail the build on any compile error, since YARA-X rejects patterns that classic YARA silently accepted.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `yara-and-yara-x-scanner-engineering` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable scan/compile commands and output shapes | [`QUERIES.md`](QUERIES.md) | CLI invocations, ndjson output, and CI gate commands |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `yr scan` flags, `yara_x` class surface, version pins |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Slow-rule and false-positive incidents from disclosed corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff when a scan must be stopped or re-scoped |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** `yara-x` >= 1.23 Python bindings (`yara_x.Compiler`, `yara_x.Scanner`, `set_timeout`, `max_matches_per_pattern`) with classic `yara-python` retained only for process-memory scans
- **Mandatory Self-Validation Command:** `python -m py_compile yara_scan_gate.py; yr compile rules/`

1. **Confirm the inputs.** Establish the rule tree path, the target corpus (files, directories, or a scan list), whether the target is on-disk or in-memory, and the acceptable per-file wall-clock budget. Confirm the `yara-x` version with `yr --version`, because atom and regex strictness moved between releases.
2. **Choose the branch.** File scanning uses `yr scan` or `Scanner.scan_file`; in-memory blob scanning uses `Scanner.scan(bytes)`; archive and directory trees use `--recursive` with an explicit depth. Process memory is the one branch that leaves YARA-X entirely.
3. **Define how to validate the script.** Compile the whole rule tree first — a rule that fails to compile must never reach the scanner. Then run one positive sample and one clean-ware sample per rule, assert the positive matches and the clean file does not, and record the elapsed time so the next run has a baseline. `yr scan --profiling` names the slowest rules.
4. **Name the stop condition.** Stop when a rule exceeds the per-file timeout, when `--profiling` reports a rule dominating total scan time, when a rule matches a clean-ware corpus item, or when compilation fails after a rule edit. Do not raise the global timeout to make a red build green.
5. **State what counts as a working tool.** A working scanner compiles the rule set once, exits `0` only when the positive fixture matched and the benign fixture did not, exits `1` on a missing expected match or an unexpected false positive, and exits `2` on a compile error or unreadable path. Matches are emitted as one JSON object per line with rule identifier, namespace, and offset.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `yara_x.Compiler().build()` returning a `Rules` object | Proves the rule tree compiled as a unit; reuse across targets is what makes throughput achievable |
| `yr scan --profiling` per-rule timing | Proves which single rule dominates scan cost, separating rule defects from I/O-bound work |
| `Scanner.set_timeout(seconds)` / `max_matches_per_pattern()` | Proves each target is bounded, so a crafted file cannot hold the scanner indefinitely |
| `pe.imphash()` / `pe.sections[i].entropy` in the condition | Proves the match is anchored to structural evidence, cutting false positives from string-only rules |
| Positive-plus-clean-ware fixture differential | Proves the rule discriminates, not merely matches |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: recompiles per file, no timeout, no bound on matches, and reads whole files into RAM
import yara

def scan(paths):
    for path in paths:
        rules = yara.compile(filepath="rules/all.yar")      # recompiled every target
        matches = rules.match(path)                          # unbounded runtime
        print(path, matches)
```

**Production-Grade Starter Skeleton (USE):**

```python
# yara_scan_gate.py - Exit 0 expected differential held, 1 mismatch, 2 env/compile error
import json
import pathlib
import sys

import yara_x

def build_rules(rule_paths: list[pathlib.Path]) -> yara_x.Rules:
    compiler = yara_x.Compiler()
    for path in rule_paths:
        compiler.new_namespace(path.stem)
        compiler.add_source(path.read_text(encoding="utf-8"))
    return compiler.build()

def scan_one(rules: yara_x.Rules, target: pathlib.Path, timeout_s: int = 30) -> list[dict]:
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(timeout_s)
    scanner.max_matches_per_pattern(100)
    results = scanner.scan_file(str(target))
    out = []
    for rule in results.matching_rules:
        out.append({
            "rule": rule.identifier,
            "namespace": rule.namespace,
            "target": str(target),
            "patterns": len(rule.patterns),
        })
    return out

def gate(rule_dir: pathlib.Path, positive: pathlib.Path, benign: pathlib.Path) -> int:
    rule_paths = sorted(rule_dir.glob("*.yar")) + sorted(rule_dir.glob("*.yara"))
    if not rule_paths or not positive.is_file() or not benign.is_file():
        sys.stderr.write("fatal: missing rule files or fixture\n")
        return 2
    try:
        rules = build_rules(rule_paths)
    except yara_x.CompileError as exc:
        sys.stderr.write(f"fatal: compile error: {exc}\n")
        return 2
    hits_positive = scan_one(rules, positive)
    hits_benign = scan_one(rules, benign)
    for row in hits_positive:
        print(json.dumps({**row, "fixture": "positive"}))
    for row in hits_benign:
        print(json.dumps({**row, "fixture": "benign"}))
    if not hits_positive:
        sys.stderr.write("fail: rule set did not match the positive fixture\n")
        return 1
    if hits_benign:
        sys.stderr.write("fail: rule set matched the clean-ware fixture\n")
        return 1
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.stderr.write("usage: yara_scan_gate.py <rule_dir> <positive> <benign>\n")
        raise SystemExit(2)
    raise SystemExit(gate(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])))
```

```yara
rule Suspicious_PE_Imphash_Match : apt_fixture
{
    meta:
        author = "detection-engineering"
        description = "Structural match: import hash plus a named section, no bare string"
    condition:
        pe.is_pe and
        pe.imphash() == "b5b3a1e1b2b3c4d5e6f708192a3b4c5d" and
        pe.number_of_sections > 3 and
        for any section in pe.sections : ( section.entropy > 7.2 )
}
```

**Why this matters:** the compiled `Rules` object is built once and shared, every target is time-bounded, and the gate fails on a false positive as loudly as on a missed positive — the two failures a signature team actually cares about.

## When It Is NOT This Issue

- **A rule that never matches because the target is packed** — the observable is identical to a bad rule, so confirm entropy/section names first; a packed sample defeats atom extraction without any rule defect.
- **`yara-x` refusing a rule that classic YARA accepted** — YARA-X enforces stricter regex escaping, so a ported rule fails at compile, not at scan time. That is a format-migration task, not a performance bug.
- **Slow scans on network storage** — per-rule timing from `--profiling` will look uniform; the cost is I/O, so no rule edit helps.
- **A "false positive" that is actually a stale compiled ruleset** — loading a `.yarc` with `-C` scans with the rules compiled earlier; confirm the compiled artifact's age before editing the source rule.
- **Process-memory scanning requests** — the YARA-X Python bindings do not cover it; recommending a flag that does not exist is the failure mode here.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER claim `yara-python` and `yara_x` are interchangeable — the APIs differ (`yara.compile`/`rules.match` versus `Compiler`/`Scanner`) and rule syntax strictness differs.
- NEVER recommend a flag you have not confirmed on the installed `yr` version; the CLI is subcommand-based (`yr scan`, `yr compile`) and flags were added across 1.x releases.
- NEVER present a rule that only matches a bare common string as production signature work — it is a false-positive generator, and clean-ware benchmarking will prove it.
- NEVER state a scan "passed" without naming both fixtures (positive and benign) and the timeout used.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Rule tree path, target type (file/blob/memory), and per-file time budget for `yara-and-yara-x-scanner-engineering` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The rule, scanner, or CI gate is specific and runnable (no generic 'add more context' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: yara-and-yara-x-scanner-engineering
- **Target Stack & Schema**: yara-x Python bindings (Compiler/Scanner) with classic yara-python only for memory scans
- **Safety, Scope & Exit-Code Guards**: [Rule-path scope, per-target timeout, match-count cap, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Clean-ware fixture, packed samples, stricter YARA-X regex syntax]
- **Implementation**:
  [Runnable rule or scanner following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile yara_scan_gate.py; yr compile rules/`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md) - Detections expressed as portable rules instead of file signatures
- [`zeek-script-and-notice-development`](../zeek-script-and-notice-development/SKILL.md) - Network-side signature and notice framework
- [`suricata-lua-and-rule-qa-tooling`](../suricata-lua-and-rule-qa-tooling/SKILL.md) - The other rule-QA harness in this family
- [`static-pe-elf-apk-feature-extractor-scripting`](../static-pe-elf-apk-feature-extractor-scripting/SKILL.md) - Produces the structural features (`imphash`, entropy) rules anchor on
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Consumes scan results as normalized events
- [`windows-forensic-artifact-parser-development`](../windows-forensic-artifact-parser-development/SKILL.md) - Supplies hashes and manifest records for scan targets

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `yara-and-yara-x-scanner-engineering` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-400`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
