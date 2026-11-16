---
name: binary-ninja-il-automation-scripting
description: "Authors Binary Ninja Python plugins and headless scripts over Medium/High Level IL (`mlil`, `hlil`): SSA variable def-use tracing, automated type annotation, sink parameter Audit reports, and custom architecture/firmware loader views. Use when scripting Binary Ninja static analysis."
family: security-assessment-tooling-and-automation
tier: leaf
triggers: ["binary ninja script", "binja hlil", "mlil ssa", "binaryview python"]
cwe: [CWE-119]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Binary Ninja Il Automation Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Binary Ninja exposes a linear IL (LLIL/MLIL/HLIL) plus a static single-assignment form through its Python API, so an audit script can walk instructions, follow variable definitions, and classify call sites without pattern-matching raw bytes. The technique is choosing the IL level that answers the question: LLIL for register-level effects, MLIL for memory and stack variables, HLIL for source-shaped control flow.

- **IL level decides the answer.** Register aliasing disappears at MLIL and above; a size or bounds question asked at LLIL re-derives what MLIL already has.
- **SSA makes def-use queries cheap.** `ssa_form` on MLIL/HLIL turns a variable into a definition chain, which is how a script proves a value flows from a call result into a length argument.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is about register or flag effects **THEN** stay at LLIL; **IF** it is about a stack variable's value **THEN** use MLIL.
2. **IF** the binary is stripped and analysis has not finished **THEN** wait for `bv.update_analysis_and_wait()` before reading IL, otherwise functions are half-analysed.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a loaded BinaryView with completed analysis and the IL level chosen for the question — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Binary Ninja Python API (`binaryninja`), `MediumLevelILFunction.ssa_form`, `HighLevelILFunction` for source-shaped queries
- **Mandatory Self-Validation Command:** `python -c "import binaryninja; print(binaryninja.core_version())"`

1. Confirm the target surface: load the BinaryView, wait for analysis, and record the architecture and calling convention that the IL will assume.
2. Choose the branch: LLIL for instruction effects, MLIL for stack and memory variables, HLIL for control-flow shape; record the choice because results are not comparable across levels.
3. Define the differential: compare the call-site inventory before and after your classification rule, and require the rule to change only the sites it claims to classify.
4. Name the stop condition: a function count or a depth limit on the def-use walk, so a recursive wrapper cannot loop forever.
5. Prove it: print the defining instruction and the address of both the source and the sink for every classified call site, so a reviewer can open the same address and see the same thing.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `bv.update_analysis_and_wait()` | Blocks until analysis completes; reading IL earlier yields partially lifted functions and wrong def-use results. |
| `func.mlil.ssa_form` | Gives each definition its own variable, which is what makes a def-use walk terminate and stay precise. |
| `MediumLevelILCall and MediumLevelILOperation.MLIL_CALL` | Identifies call sites at the level where arguments are already resolved into variables. |
| `hlil.instructions for a source-shaped loop` | Useful for spotting unbounded loop shapes without reconstructing them from basic blocks. |

## Worked Contrast

**Raw-Byte Pattern Match for a Dangerous Call:**

```python
data = open("target.bin", "rb").read()
if b"\xff\xd0" in data:  # BUG: any indirect call matches, no context, no argument knowledge
    print("unsafe indirect call")
```

**IL-Level Call Classification With Def-Use:**

```python
import binaryninja as bn

bv = bn.load("target.bin")
bv.update_analysis_and_wait()
for func in bv.functions:
    mlil = func.mlil
    if mlil is None:
        continue
    ssa = mlil.ssa_form
    for block in ssa.basic_blocks:
        for insn in block:
            if insn.operation != bn.MediumLevelILOperation.MLIL_CALL:
                continue
            target = insn.dest
            print(hex(insn.address), func.name, target)
```

**Why this matters:** An indirect-call byte pattern matches every virtual dispatch in the binary, so the output cannot be triaged. Walking MLIL call instructions gives an address and a resolved destination per site, which is the smallest unit a reviewer can confirm or dismiss in the UI.

## When It Is NOT This Issue

- **IL read before analysis finished.** Findings from a half-analysed function are artefacts of the lift, not properties of the binary; always wait for analysis.
- **Call classified at LLIL then reported as an argument flow.** LLIL has no variable resolution, so an apparent argument is a register at that instant, not the call's argument.
- **Inlined library code counted as application code.** statically linked helpers inflate the call inventory; require the function to be reachable from an exported entry.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `BinaryViewType` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `binary-ninja-il-automation-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: binary-ninja-il-automation-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `BinaryViewType`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile binary_ninja_il_automation.py; python binary_ninja_il_automation.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `binary-ninja-il-automation-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
