---
name: go-ssa-and-rust-clippy-security-lints
description: "Authors Go `golang.org/x/tools/go/analysis` passes (including SSA inspection) and Rust custom `dylint`/Clippy lints: catching `unsafe` FFI invariant gaps, unchecked `sql.DB.Query` concatenation, goroutine context leaks, and weak `math/rand` crypto usage. Use when enforcing compile-time security invariants in Go or Rust."
family: security-assessment-tooling-and-automation
tier: leaf
triggers: ["go analysis linter", "go ssa security", "rust dylint", "custom clippy lint"]
cwe: [CWE-119]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Go SSA and Rust Clippy Security Lints - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Custom static analysis inside the compiler toolchain: a Go `analysis.Analyzer` that consumes SSA (`buildssa.Analyzer`) to find values flowing into unsafe calls, and a Rust lint crate (dylint or a `LateLintPass`) that inspects HIR/MIR for the same class of mistake. The advantage over an external scanner is type information: the analyzer sees resolved types and real call targets, so a rule can distinguish a dangerous `unsafe` block from a safe wrapper.

- **Types make the rule precise.** An SSA or HIR rule can require the callee's resolved package path, which removes most false positives a text rule cannot avoid.
- **Lints must be cheap.** Analyzers run on every build; a rule that walks all functions repeatedly turns a fast build into a slow one and gets disabled.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the rule needs dataflow **THEN** build on `buildssa.Analyzer` and inspect `ssa.Value` operands rather than matching AST shapes.
2. **IF** the rule is Rust and must run without nightly **THEN** use dylint, which ships the lint as a dynamic library against a pinned toolchain.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a compiling target package or crate, and one rule with a positive and a negative fixture — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Go `golang.org/x/tools/go/analysis` with `buildssa`, plus `analysistest` fixtures; Rust dylint or `rustc_lint::LateLintPass` with `ui_test` fixtures
- **Mandatory Self-Validation Command:** `go vet -vettool=$(which mylint) ./...`

1. Confirm the target surface: name the exact call or type the rule targets, and confirm its resolved import path in the target codebase.
2. Choose the branch: SSA rule for value flow, AST rule for syntactic patterns, HIR lint for Rust expression shapes, MIR lint when borrow or drop behaviour matters.
3. Define the differential: run the analyzer on a package with the fixture that must be reported and one that must not; the rule is wrong if either result differs from the fixture annotation.
4. Name the stop condition: a fixture pair per rule branch, and a build-time budget so the analyzer stays in the default build.
5. Prove it: the fixture files carry `// want` annotations (Go) or expected stderr (Rust), so the pass/fail is machine-checked rather than eyeballed.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `var Analyzer = &analysis.Analyzer{Requires: []*analysis.Analyzer{buildssa.Analyzer}}` | Declares the SSA dependency; without it the analyzer only sees syntax. |
| `analysistest.Run(t, dir, Analyzer, "pkg")` | Fixture-driven test where `// want` comments are the expected findings. |
| `LateLintPass::check_expr with cx.tcx` | Rust lint entry with type context, which is what separates a real call from a shadowing method. |
| `declare_lint! and register_lints` | Registers the lint so it appears in normal compiler output. |

## Worked Contrast

**Text Rule Masquerading as a Lint:**

```go
// BUG: matches the identifier text anywhere, including comments and a locally defined safe helper
func run(pass *analysis.Pass) (any, error) {
    for _, f := range pass.Files {
        ast.Inspect(f, func(n ast.Node) bool {
            if id, ok := n.(*ast.Ident); ok && id.Name == "Unsafe" {
                pass.Reportf(id.Pos(), "unsafe call")
            }
            return true
        })
    }
    return nil, nil
}
```

**SSA Rule That Resolves the Callee:**

```go
var Analyzer = &analysis.Analyzer{
    Name:     "unsafecall",
    Doc:      "report calls into package unsafe",
    Requires: []*analysis.Analyzer{buildssa.Analyzer},
    Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
    ssa := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
    for _, fn := range ssa.SrcFuncs {
        for _, b := range fn.Blocks {
            for _, ins := range b.Instrs {
                call, ok := ins.(ssa.CallInstruction)
                if !ok {
                    continue
                }
                if callee := call.Common().StaticCallee(); callee != nil &&
                    strings.HasPrefix(callee.Pkg.Pkg.Path(), "unsafe") {
                    pass.Reportf(call.Pos(), "call into unsafe: %s", callee.Name())
                }
            }
        }
    }
    return nil, nil
}
```

**Why this matters:** An identifier match cannot tell a call into package `unsafe` from an unrelated variable named `Unsafe`, and it reports comments. Resolving the callee through SSA gives the package path, so the rule's output is exactly the construct it claims to find and the fixture pair proves both directions.

## When It Is NOT This Issue

- **Rule fires on generated code.** Protobuf or mock output is not hand-written; exclude generated files by header marker, not by path guess.
- **Shadowed identifier.** A local function with the same name as the dangerous callee is not a finding; require the resolved package path.
- **Lint enabled only in a strict profile.** A finding from a lint the build does not enable by default is advisory, not a build break.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `analysis.Analyzer` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `go-ssa-and-rust-clippy-security-lints` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: go-ssa-and-rust-clippy-security-lints
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `analysis.Analyzer`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile go_ssa_and_rust.py; python go_ssa_and_rust.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `go-ssa-and-rust-clippy-security-lints` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-119`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
