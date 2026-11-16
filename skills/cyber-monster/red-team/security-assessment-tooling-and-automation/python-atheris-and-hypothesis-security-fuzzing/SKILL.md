---
name: python-atheris-and-hypothesis-security-fuzzing
description: "Writes coverage-guided Python fuzzers with `atheris` and stateful property-based security tests with `hypothesis`: parser differential testing (WAF vs backend URL/JSON/XML parsers), round-trip serialization invariants, and crash reproduction shrinking. Use when fuzzing Python libraries or parser boundaries."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["atheris fuzzing", "hypothesis property testing", "python fuzzer", "differential parser fuzzing"]
cwe: [CWE-20]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Python Atheris and Hypothesis Security Fuzzing - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Property-based and coverage-guided testing of Python code: Hypothesis generates inputs from strategies and shrinks any failure to a minimal example, while Atheris wraps the same idea around libFuzzer for byte-level parsers. The audit-relevant distinction is that Hypothesis tests a stated property over a typed input space, and Atheris explores a byte space without a specification — both need an oracle that a failure is unambiguous.

- **Shrinking is the deliverable.** Hypothesis reports the minimal failing example; an assertion that fails on any of a million inputs is only actionable once minimised.
- **Atheris needs a hard oracle.** Under libFuzzer any uncaught exception is a crash, so the harness must not raise on ordinary invalid input.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the property is expressible over typed values **THEN** use Hypothesis strategies and `@given`, and let shrinking find the boundary.
2. **IF** the target consumes bytes from an untrusted source **THEN** use Atheris with `FuzzedDataProvider` and treat only unexpected exceptions as findings.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a pure function under test, a property that can fail, and a maximum example size — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Hypothesis 6.x (`@given`, `st.binary`, `RuleBasedStateMachine`, `.example()`), Atheris (`atheris.Setup`, `atheris.FuzzedDataProvider`)
- **Mandatory Self-Validation Command:** `pytest --hypothesis-seed=0 -q tests/test_props.py`

1. Confirm the target surface: identify a function with no IO and a property that the function should satisfy for all inputs.
2. Choose the branch: Hypothesis for typed values and stateful sequences, Atheris for raw byte parsers, and `RuleBasedStateMachine` when the property is about a sequence of operations.
3. Define the differential: run the property on the current code and on a known-correct reference; the reference must pass, and any failure in the target is reported with its minimised input.
4. Name the stop condition: a deadline and a `max_examples` budget, plus a maximum input size so shrinking stays fast.
5. Prove it: keep the minimised failing example, add it as a regression test, and record the Hypothesis seed so the run reproduces.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `@given(st.binary(max_size=4096))` | Bounds the example size so shrinking and replay stay fast and the input stays in the parser's real domain. |
| `RuleBasedStateMachine with @rule` | Tests sequences of operations, which is where stateful accounting bugs live. |
| `atheris.Setup(argv, TestOneInput)` | Wires the Atheris harness into libFuzzer's command line, including corpus directories. |
| `FuzzedDataProvider(data).ConsumeBytes(...)` | Consumes a structured prefix so the fuzzer can mutate configuration and payload separately. |

## Worked Contrast

**Property That Swallows Every Exception:**

```python
from hypothesis import given, strategies as st

@given(st.binary())
def test_parse(data):
    try:
        parse(data)
    except Exception:
        pass  # BUG: every failure is hidden, so the property can never fail
```

**Property With a Stated Postcondition and Bounded Input:**

```python
import pytest
from hypothesis import given, settings, strategies as st

@given(st.binary(max_size=4096))
@settings(max_examples=500, deadline=2000)
def test_parse_is_total(data):
    try:
        result = parse(data)
    except ValueError:
        return
    assert isinstance(result, dict)
    assert result.get("len", 0) <= len(data)
```

**Why this matters:** Catching every exception turns the property into a no-op and the green run into a false assurance. Declaring which exception is expected and asserting a postcondition makes the property falsifiable, and bounding the input size keeps the counterexample small enough to read.

## When It Is NOT This Issue

- **Failure caused by the test's own assumption.** A property that asserts on values outside the function's contract is a broken test, not a bug.
- **Deadline exceeded read as a hang.** Hypothesis deadlines measure the test harness, not production latency; raise the deadline or mark the test slow.
- **Atheris crash from an unhandled parse error.** Ordinary invalid input that raises is a harness defect, not a finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `atheris.Setup` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `python-atheris-and-hypothesis-security-fuzzing` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: python-atheris-and-hypothesis-security-fuzzing
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `atheris.Setup`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile python_atheris_and_hypothesis.py; python python_atheris_and_hypothesis.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `python-atheris-and-hypothesis-security-fuzzing` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
