---
name: capstone-and-lief-binary-inspector-scripting
description: "Builds fast standalone binary security inspectors in Python using `lief`, `capstone`, and `pyelftools`/`pefile`: auditing NX/PIE/RELRO/ASLR/CFG/signature flags across entire firmware images or build artifacts, symbol import auditing, and section entropy reporting. Use when automating binary hardening checks."
family: security-assessment-tooling-and-automation
tier: leaf
triggers: ["lief python", "capstone disassembly script", "pe elf security checker", "firmware binary audit"]
cwe: [CWE-693]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Capstone and Lief Binary Inspector Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Static inspection of a PE, ELF, or Mach-O image with LIEF for structure (sections, imports, relocations, protections) and Capstone for instruction-level decoding of specific ranges. The audit question is almost always a mitigation or import question: is NX set, is PIE enabled, is CFG present, which dangerous imports are resolved, and what do the bytes at a given export actually do.

- **Structure before bytes.** LIEF answers the mitigation and import questions from headers; Capstone is only needed for the handful of ranges those answers implicate.
- **Header flags are not behaviour.** `has_nx` and `is_pie` describe what the loader may enforce, not what the code does; pair each flag with the code path that would exploit its absence.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is which mitigations a binary has **THEN** read LIEF header properties and stop there.
2. **IF** the question is what a specific export does **THEN** disassemble only that symbol's range, bounded by its size from the symbol table.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a parsed binary image with a symbol or section table, and a defined question about one mitigation or one import — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** LIEF (`lief.parse`, `binary.has_nx`, `binary.is_pie`) and Capstone (`Cs`, `Cs(CS_ARCH_X86, CS_MODE_64)`) with explicit address ranges
- **Mandatory Self-Validation Command:** `python -c "import lief, capstone; print(lief.__version__, capstone.__version__)"`

1. Confirm the target surface: parse the image, record format, architecture, and the hash of the file so the report refers to one artefact.
2. Choose the branch: mitigation inventory (headers only), import triage (import table), or disassembly (one symbol range).
3. Define the differential: compare the same property between the shipped binary and a reference build; a mitigation present in reference and absent here is the finding.
4. Name the stop condition: one symbol or one section per pass, with the byte range stated, so the disassembly cannot silently drift into unrelated code.
5. Prove it: print the header field or the decoded instructions with addresses, and cite the file hash, so the claim survives a rebuild.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `lief.parse(path).header.machine_type` | Confirms architecture before any decoding; a wrong mode produces plausible-looking garbage. |
| `binary.has_nx / is_pie / has_cfg` | Mitigation inventory straight from headers, which is the only reproducible source for these claims. |
| `capstone.Cs(CS_ARCH_X86, CS_MODE_64).disasm(code, addr)` | Decodes exactly the bytes handed to it at the stated address; scoping the range is what keeps the output reviewable. |
| `binary.imported_functions` | Lists resolved imports; dangerous-import findings must name the symbol and the calling site. |

## Worked Contrast

**Mitigation Claim From a Grep of the File:**

```python
data = open("app.exe", "rb").read()
print("ASLR" if b"DYNAMICBASE" in data else "no ASLR")  # BUG: the string can appear in a resource or a debug path
```

**Header-Derived Mitigation Inventory Plus Bounded Disassembly:**

```python
import lief
import capstone

binary = lief.parse("app.exe")
print(binary.header.machine_type, hex(binary.optional_header.imagebase))
print("nx", binary.has_nx, "pie", binary.is_pie)

func = next(s for s in binary.symbols if s.name == "parse_record")
code = binary.get_content_from_virtual_address(func.value, func.size)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for insn in md.disasm(bytes(code), func.value):
    print(hex(insn.address), insn.mnemonic, insn.op_str)
```

**Why this matters:** A mitigation string inside a file proves nothing: packers, resources, and debug directories all carry such strings. Reading the optional header gives the loader's actual decision, and bounding the disassembly to a symbol's range keeps every printed instruction attributable to one function.

## When It Is NOT This Issue

- **Packed or self-modifying image.** Header flags describe the stub; mitigation claims about packed code require unpacking first.
- **`has_nx` false on a loader that enforces NX.** Some runtimes set the flag at load; check the loader or the process, not the file alone.
- **Import present but unreachable.** A dangerous import in a statically linked blob is only a finding when a reachable path calls it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `lief.parse` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `capstone-and-lief-binary-inspector-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: capstone-and-lief-binary-inspector-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `lief.parse`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile capstone_and_lief_binary.py; python capstone_and_lief_binary.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `capstone-and-lief-binary-inspector-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
