---
name: idapython-automation-scripting
description: "Writes modern IDAPython 8/9 automation scripts (`ida_bytes`, `ida_funcs`, `ida_hexrays`, `ida_typeinf`, `ida_xref`, `idautils` — avoiding legacy `idc`): batch Hex-Rays `ctree_visitor_t` sink hunting, struct/vtable reconstruction, string/config cross-reference mapping, and headless `idalib`/`idat` batch analysis. Use when automating IDA Pro binary analysis."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["idapython script", "ida_hexrays", "ctree_visitor_t", "idalib batch", "idapython automation"]
cwe: [CWE-119]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Idapython Automation Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`static-pe-elf-apk-feature-extractor-scripting`](../../../blue-team/security-automation-and-tool-development/static-pe-elf-apk-feature-extractor-scripting/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Scripted IDA Pro analysis through IDAPython: iterate functions with `idautils.Functions`, walk cross-references with `idautils.XrefsTo`, decompile to a ctree with `ida_hexrays.decompile`, and rename or comment as a reviewable output. The audit use is bulk triage — find every call site of a dangerous import, every function that writes to a global, every handler reachable from a dispatch table — and hand a shortlist to a human.

- **Wait for auto-analysis.** `ida_auto.auto_wait()` before reading anything; a script that runs during analysis sees half-built functions and wrong xrefs.
- **Annotations are the output.** Renames and comments persist in the database, so the next analyst inherits the triage instead of repeating it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question needs source-like expressions **THEN** use `ida_hexrays.decompile` and a `ctree_visitor_t`, not the disassembly text.
2. **IF** the script mutates names or comments **THEN** save the database to a copy first, so triage does not overwrite the original review state.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`static-pe-elf-apk-feature-extractor-scripting`](../../../blue-team/security-automation-and-tool-development/static-pe-elf-apk-feature-extractor-scripting/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a loaded database with completed auto-analysis, and a target symbol or address range — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** IDA Pro 9.x IDAPython (`ida_auto`, `idautils`, `ida_funcs`, `ida_hexrays`, `ida_typeinf`)
- **Mandatory Self-Validation Command:** `python idat -A -Saudit.py target.i64`

1. Confirm the target surface: resolve the import or global by name, record its address, and confirm auto-analysis finished.
2. Choose the branch: xref enumeration for call sites, ctree visit for expression-level flow, or type application (`ida_typeinf`) when the decompiler output needs structure before it is readable.
3. Define the differential: run the script against the pre-patch and post-patch databases; the flagged address set must change only by the addresses the patch touched.
4. Name the stop condition: one symbol per pass with a bounded xref count, so a widely used import does not produce an untriageable list.
5. Prove it: emit address, function name, and the instruction or ctree expression that triggered the flag, and save them as comments in the database.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ida_auto.auto_wait()` | Blocks until auto-analysis finishes; every later API result depends on it. |
| `idautils.XrefsTo(ea)` | Enumerates call and data references to one address, which is the unit of call-site triage. |
| `ida_hexrays.decompile(func_ea)` | Returns a cfunc whose ctree can be walked for expression-level questions. |
| `idc.set_name and idc.set_cmt` | Persist triage results so the next analyst starts from the annotated database. |

## Worked Contrast

**Script That Runs Before Analysis and Trusts Text:**

```python
import idautils, idc

for ea in idautils.Functions():
    text = idc.get_func_off_str(ea)
    if text and "memcpy" in text:  # BUG: no auto_wait, and a name substring is not a call
        print(hex(ea))
```

**Analysis-Gated Xref Triage With Persisted Annotations:**

```python
import ida_auto, ida_funcs, idautils, idc

ida_auto.auto_wait()
target = idc.get_name_ea_simple("memcpy")
if target != idc.BADADDR:
    for xref in idautils.XrefsTo(target, 0):
        func = ida_funcs.get_func(xref.frm)
        if func is None:
            continue
        name = idc.get_func_name(func.start_ea)
        idc.set_cmt(xref.frm, "memcpy call site", 0)
        print(hex(xref.frm), name)
```

**Why this matters:** A function name containing the target string is not a call, and reading before analysis finishes produces missing xrefs. Waiting for analysis and enumerating real cross-references yields the exact call instruction addresses, and writing them back as comments makes the triage durable.

## When It Is NOT This Issue

- **Xref from a thunk or import stub.** The stub is not the semantic call site; follow to the caller before reporting.
- **Script run mid-analysis.** Missing xrefs are an artefact of timing, not the absence of calls.
- **Decompiler name read as source symbol.** Stripped and optimised binaries get invented names; confirm behaviour from the ctree.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER import legacy `idc` wrappers (`idc.GetFunctionName`, `idc.Byte`) — use typed `ida_*` modules.
- NEVER inspect functions in batch scripts before calling `ida_auto.auto_wait()`.
- NEVER assume 32-bit addresses — format `ea_t` values with `f'{ea:#x}'`.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `idapython-automation-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: idapython-automation-scripting
- **Target Stack & Schema**: IDA Pro 8.3+/9.x Python 3 SDK (`ida_bytes`, `ida_funcs`, `ida_hexrays`, `ida_typeinf`, `ida_xref`, `idautils`, `ida_auto`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile ida_triage.py`
```

## Related Sub-Skills

- [`static-pe-elf-apk-feature-extractor-scripting`](../../../blue-team/security-automation-and-tool-development/static-pe-elf-apk-feature-extractor-scripting/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `idapython-automation-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
