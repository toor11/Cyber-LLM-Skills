---
name: go-fuzz-and-cargo-fuzz-harness-development
description: "Develops native Go `testing.F` (`go test -fuzz`) and Rust `cargo-fuzz` (`libfuzzer-sys` + `Arbitrary` derive) harnesses: structured input generation, panic/OOM/allocation bounds checks, and regression corpus replay in CI. Use when fuzzing Go packages or Rust crates."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["go test fuzz", "testing.f go", "cargo fuzz", "arbitrary crate rust", "rust fuzz harness"]
cwe: [CWE-190]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Go Fuzz and Cargo Fuzz Harness Development - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Coverage-guided fuzzing of Go and Rust targets through the language-native harness: `func FuzzX(f *testing.F)` with `f.Fuzz` seed corpus in Go, and `fuzz_target!` with `#[derive(Arbitrary)]` in Rust. The harness converts raw bytes into a typed input, so the engineering decision is how much structure the conversion enforces: too little and the parser rejects almost every input before reaching the bug, too much and the fuzzer can no longer mutate into interesting states.

- **The byte-to-type conversion is the harness.** Everything the fuzzer can reach is decided by how you turn `[]byte` into the target's input type; a strict conversion starves the corpus.
- **Panics are the oracle.** A fuzz target's value is that any panic, index-out-of-range, or assertion failure is automatically a finding, so the harness must not swallow errors.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target parses a structured format **THEN** fuzz the raw bytes and let the parser do the shaping, adding a seed corpus of valid samples rather than building a generator.
2. **IF** the crash needs a valid header **THEN** split the input into a header slice and a body slice so mutations preserve the header more often.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a target function that accepts bytes without side effects, and at least one seed input that reaches the parser's main loop — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Go 1.20+ native fuzzing (`func Fuzz(f *testing.F)`, `go test -fuzz=Fuzz`) and cargo-fuzz (`fuzz_target!`, `arbitrary::Arbitrary`, `cargo +nightly fuzz run`)
- **Mandatory Self-Validation Command:** `go test -run=^$ -fuzz=FuzzParse -fuzztime=30s ./...`

1. Confirm the target surface: pick one pure function that takes bytes and returns a value or an error, and make sure it touches no network, filesystem, or global state.
2. Choose the branch: raw-bytes harness for parsers, split-slice harness for header-plus-body formats, and `Arbitrary`-derived structs in Rust when field relationships matter more than byte fidelity.
3. Define the differential: run the harness on the seed corpus with `-run` only (no fuzzing) and confirm it executes the parser, then run the fuzzer; a corpus that never reaches the parser produces a green run that means nothing.
4. Name the stop condition: a fuzz time budget and a crash count of one; stop and triage on the first reproducible input rather than letting the campaign run on.
5. Prove it: keep the crasher input file, replay it as a unit test, and confirm the same panic with the minimised bytes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `func FuzzParse(f *testing.F)` | Go's native entry point; `f.Add` seeds turn real samples into mutation starting points. |
| `f.Fuzz(func(t *testing.T, data []byte) {...})` | The per-input body; any panic here is recorded as a crasher in testdata/fuzz. |
| `fuzz_target!` byte-slice closure | cargo-fuzz entry point; returning normally is fine, panicking is the finding. |
| `#[derive(Arbitrary, Debug)] struct Input` | Generates typed inputs from bytes, which lets the fuzzer work on fields instead of raw offsets. |

## Worked Contrast

**Harness That Swallows Every Error:**

```go
func FuzzParse(f *testing.F) {
    f.Add([]byte("a=b"))
    f.Fuzz(func(t *testing.T, data []byte) {
        _, err := Parse(data)
        if err != nil {
            return // BUG: an index panic inside Parse is recovered nowhere, but errors are hidden
        }
    })
}
```

**Harness That Splits Header From Body and Keeps Panics:**

```go
func FuzzParse(f *testing.F) {
    f.Add([]byte("v=1"), []byte("a=b"))
    f.Fuzz(func(t *testing.T, head, body []byte) {
        if len(head) == 0 {
            return
        }
        _, _ = ParseWithHeader(head, body)
    })
}
```

**Why this matters:** The first harness spends most mutations on inputs the parser rejects at byte zero, so coverage stays flat. Splitting the input lets the fuzzer keep a mutation-shaped header while exploring the body grammar, and leaving the call unguarded means a panic surfaces as a crasher instead of an ignored error.

## When It Is NOT This Issue

- **Panic in the harness, not the target.** A conversion helper that panics on short input is a harness bug and produces crashers nobody can fix in production code.
- **Seed corpus never reaches the parser.** A campaign with zero corpus coverage is measuring the seed, not the target.
- **Timeout counted as a bug.** A hang in a fuzz run may be the fuzzer's own slow path; reproduce with the single input before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `func Fuzz` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `go-fuzz-and-cargo-fuzz-harness-development` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: go-fuzz-and-cargo-fuzz-harness-development
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `func Fuzz`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile go_fuzz_and_cargo.py; python go_fuzz_and_cargo.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `go-fuzz-and-cargo-fuzz-harness-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
