---
name: angr-and-z3-constraint-solver-scripting
description: "Develops Python `angr` symbolic reachability scripts and `z3-solver` bitvector/array models: bounded `SimulationManager` exploration with loop limiters (`Veritesting`, `LengthLimiter`), `SimProcedure` stubs to avoid path explosion, and protocol/crypto invariant verification. Use when scripting constraint solving."
family: security-assessment-tooling-and-automation
tier: leaf
triggers: ["angr script", "z3 solver python", "simulationmanager angr", "bitvec z3"]
cwe: [CWE-20]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Angr and Z3 Constraint Solver Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Symbolic execution of a target function with angr, plus SMT solving of the path constraint that guards a comparison, an index bound, or a checksum branch. The work is to pick the right entry state (address, calling convention, stdin vs argv), bound the state explosion with a find/avoid pair, and then let z3 answer whether an input exists that reaches the guarded branch, rather than fuzzing until an input happens to land there.

- **State budget is the design.** Every symbolic run is defined by `find=`, `avoid=`, and a step cap; without the avoid set the solver explores error paths and the result is an unrelated crash, not a reachability proof.
- **Solver model is the deliverable.** A `z3` model is only evidence when it is concretely replayed through the real binary and produces the guarded behaviour, not when `satisfiable` returns True.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the guard is a byte-wise comparison loop with a length check **THEN** model it as a `claripy` symbolic buffer and let the find address be the success branch, not the return site.
2. **IF** the constraint set is unsat but the branch is reachable manually **THEN** add the missed constraint (alignment, header field, size field) instead of raising the step cap.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a reachable guard address, a concrete calling convention, and a bounded state count — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** angr 9.x with claripy and z3 (`Project`, `SimulationManager`, `explore(find=, avoid=)`), `z3.Solver` for standalone models
- **Mandatory Self-Validation Command:** `python -c "import angr, z3; print(angr.__version__, z3.get_version_string())"`

1. Confirm the target surface: locate the comparison or bounds check in the disassembly, note the entry address, and decide whether the input arrives on stdin, in argv, or in a file the loader maps.
2. Choose the branch: symbolic stdin for parser-style targets, symbolic argv for CLI validators, or a symbolic memory region when the check reads a struct the harness must construct.
3. Define the differential: run the baseline with a benign input and record the concrete exit path; the probe is the same run with the symbolic buffer and `find` on the success address. The differential is *reached vs not reached*, not *crash vs no crash*.
4. Name the stop condition: a step or state cap plus an `avoid` set covering the error handler, so an unsat result means the guard is genuinely unsatisfiable rather than unexplored.
5. Prove it: take the z3 model, concretise it to bytes, replay it against the unmodified binary, and confirm the same branch is taken. Record the model, the replay output, and the constraint dump.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `project.factory.entry_state(stdin=...)` | Binds the symbolic buffer to the input channel the real binary uses; a mismatch here silently explores an unreachable state. |
| `simgr.explore(find=SUCCESS, avoid=ERROR)` | Makes reachability the question and error paths the excluded set, which is what keeps an unsat answer meaningful. |
| `state.solver.eval(buf, cast_to=bytes)` | Turns the model into replayable bytes; without this the result stays a claim. |
| `z3.BitVec and solver.add` | Standalone constraint modelling when you only need the arithmetic, e.g. an index bound or a checksum equation. |

## Worked Contrast

**Naive Reachability Run (no avoid set, unbounded steps):**

```python
import angr

proj = angr.Project("./validator", auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234)  # BUG: no avoid=, no step cap
if simgr.found:
    print("reachable")  # says nothing: the cap may have expired, or an error path matched
```

**Bounded Reachability With Replayable Model:**

```python
import angr

proj = angr.Project("./validator", auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFileStream)
simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=(0x401300, 0x4013a0), num_find=1)
simgr.step(n=2000) if not simgr.found else None
if simgr.found:
    found = simgr.found[0]
    candidate = found.solver.eval(found.posix.stdin.load(0, found.posix.stdin.size), cast_to=bytes)
    print(len(candidate), candidate[:16].hex())
```

**Why this matters:** The explore call is the hypothesis and the replay is the proof. An `avoid` set plus a step cap makes `simgr.found` empty mean *the guard is unsatisfiable under this model*, and printing raw model bytes forces the next step to be a concrete replay instead of a claim of exploitability.

## When It Is NOT This Issue

- **Solver timeout read as unsat.** z3 returning `unknown` after a timeout is not a proof the branch is unreachable; re-run with a longer budget or a narrower constraint before writing a non-finding.
- **Symbolic buffer wider than the real read.** If the binary reads 32 bytes, a 256-byte symbolic buffer explores states the loader can never produce.
- **Guard already unreachable by construction.** A comparison after a length check that rejects the failing length is a dead branch, not a weak check.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `angr.Project` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `angr-and-z3-constraint-solver-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: angr-and-z3-constraint-solver-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `angr.Project`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile angr_and_z3_constraint.py; python angr_and_z3_constraint.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `angr-and-z3-constraint-solver-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
