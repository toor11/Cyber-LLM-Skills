---
name: ghidra-headless-and-pcode-scripting
description: "Develops Ghidra `analyzeHeadless` Python/Java scripts and `DecompInterface` P-code dataflow analyzers: `Varnode` backward slicing from dangerous sinks (`strcpy`, `system`, `ioctl`), batch firmware symbol/function export, and automated patch-diff candidate scoring. Use when scaling Ghidra reverse engineering headlessly."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["ghidra headless script", "analyzeheadless", "decompinterface pcode", "varnode slice ghidra"]
cwe: [CWE-119]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Ghidra Headless and Pcode Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Scripted analysis of a program database through Ghidra's headless analyzer and its decompiler API: import a binary, run the analyzers, then drive `DecompInterface` and the P-code representation to answer structural questions (call targets, data flow, string references) across many functions without opening the GUI.

- **Headless first, GUI second.** `analyzeHeadless` with a post-script reproduces an analysis on a build agent; GUI work is for inspecting the few addresses the script flags.
- **P-code is the portable layer.** Decompiler output is textual and version-sensitive; P-code operations give a stable way to ask about calls, loads, and stores.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is a call graph **THEN** walk `PcodeOp.CALL` targets rather than parsing decompiled text.
2. **IF** the question needs source-like expressions **THEN** use `DecompInterface.decompileFunction` and accept that the text changes between Ghidra versions.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an imported program with completed analysis, and a script that names the function or address range it inspects — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Ghidra 12.x headless (`analyzeHeadless`), `DecompInterface`, `HighFunction.getPcodeOps()`, PyGhidra 3.x for Python scripting
- **Mandatory Self-Validation Command:** `analyzeHeadless <proj> audit -import target.bin -postScript Audit.py -scriptPath scripts`

1. Confirm the target surface: import the binary into a project directory, run the default analyzers, and record the program's hash and architecture.
2. Choose the branch: P-code walk for call and memory operations, decompiler output for expression-level review, or the symbol/reference tables for link-level questions.
3. Define the differential: run the script against the unpatched and patched programs and require the flagged function set to change only by the addresses the patch touched.
4. Name the stop condition: a function count or a timeout, because decompiling every function in a large binary is hours of work for little additional value.
5. Prove it: print the function entry address, the decompiler's function name, and the P-code operation that triggered the flag, so a reviewer can jump to the address.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `analyzeHeadless ... -postScript` | Runs a script after analysis on a fresh import, which is the reproducible form of an analysis. |
| `DecompInterface.decompileFunction` | Returns a `DecompileResults` whose `getHighFunction()` is the entry point to P-code. |
| `HighFunction.getPcodeOps() filtered on PcodeOp.CALL` | Portable call-site enumeration independent of decompiler text formatting. |
| `FlatProgramAPI for symbol and reference walks` | Cheap structural queries before paying for decompilation. |

## Worked Contrast

**Decompiler-Text Grep:**

```python
# BUG: matches the string in any context, breaks on decompiler formatting changes
for f in currentProgram.getFunctionManager().getFunctions(True):
    text = str(f)
    if "strcpy" in text:
        print(f.getName())
```

**P-Code Call Target Enumeration:**

```python
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

ifc = DecompInterface()
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()
for f in currentProgram.getFunctionManager().getFunctions(True):
    res = ifc.decompileFunction(f, 60, monitor)
    high = res.getHighFunction()
    if high is None:
        continue
    for op in high.getPcodeOps():
        if op.getOpcode() == op.CALL:
            print(hex(f.getEntryPoint().getOffset()), f.getName(), op.getInputs()[0])
```

**Why this matters:** String-searching a function's textual representation matches comments, symbol names, and unrelated formatting, and it breaks when the decompiler changes. P-code call operations name the actual call target per function, which is a claim a reviewer can verify at one address.

## When It Is NOT This Issue

- **Decompiled name read as a source symbol.** Stripped binaries get invented names; a `strcpy`-looking name is a suggestion.
- **Analysis not complete.** A script run before analyzers finish sees partially defined functions and misses call targets.
- **Optimised-away call.** An inlined or folded call has no `PcodeOp.CALL`; its absence does not mean the function is never invoked.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `analyzeHeadless` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ghidra-headless-and-pcode-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: ghidra-headless-and-pcode-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `analyzeHeadless`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile ghidra_headless_and_pcode.py; python ghidra_headless_and_pcode.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ghidra-headless-and-pcode-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
