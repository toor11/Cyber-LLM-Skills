---
name: libfuzzer-and-afl-harness-engineering
description: "Engineers C/C++ in-memory fuzzing harnesses (`LLVMFuzzerTestOneInput`) for libFuzzer and AFL++: `FuzzedDataProvider` structured slicing, ASAN/UBSAN/MSAN/LSAN compiler instrumentation, state reset discipline, custom mutators, and seed corpus minimization. Use when building memory-safety fuzz targets for parsers or protocols."
family: security-assessment-tooling-and-automation
tier: flagship
triggers: ["libfuzzer harness", "llvmfuzzertestoneinput", "fuzzeddataprovider", "afl++ harness", "asan fuzzing"]
cwe: [CWE-119, CWE-787]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Libfuzzer and AFL Harness Engineering - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **flagship** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Building a coverage-guided fuzz harness for native code: a `LLVMFuzzerTestOneInput` entry point plus an instrumented build (`-fsanitize=fuzzer,address,undefined` for libFuzzer, `afl-clang-fast`/LTO for AFL++), with a corpus that reaches the parser and a dictionary for the format's magic values. The harness is the specification of what the fuzzer can reach; the instrumentation decides how precisely it can steer.

- **Instrumentation mode decides the feedback signal.** PCGUARD is the default and fast; LTO mode instruments across translation units and is required when the parser is split across files.
- **Sanitizers are the oracle.** ASan for memory errors and UBSan for undefined behaviour, both with `halt_on_error=1` so a finding stops the run instead of scrolling past.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is a library function that takes a buffer and length **THEN** write the harness against that function directly, not through a CLI wrapper.
2. **IF** the parser needs a header **THEN** use `FuzzedDataProvider` to consume a fixed prefix as configuration and the remainder as the body.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a target function with a byte-buffer interface, an instrumented build, and a seed corpus that reaches the parser — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** libFuzzer with `-fsanitize=fuzzer,address,undefined`, AFL++ 5.x with `afl-clang-fast` (PCGUARD) or LTO mode, `FuzzedDataProvider` for structured inputs
- **Mandatory Self-Validation Command:** `clang -g -O1 -fsanitize=fuzzer,address,undefined fuzz.c -o fuzz && ./fuzz -runs=100`

1. Confirm the target surface: pick the library entry point, confirm it takes a buffer plus length and allocates nothing global, and record the build's sanitizer flags.
2. Choose the branch: raw-buffer harness for byte parsers, `FuzzedDataProvider` harness when the input has a configuration prefix, and a stateful harness when the protocol has handshake phases.
3. Define the differential: run the corpus with `-runs=0` to confirm every seed executes clean, then run the campaign; a crash that also reproduces from a seed is a seed defect, not a fuzzing find.
4. Name the stop condition: a time or execution budget plus a crash limit of one, and a maximum input length so the corpus does not drift into huge allocations.
5. Prove it: minimise the crasher (`-minimize_crash=1` for libFuzzer, `afl-tmin` for AFL++), replay it, and record the sanitizer report's first frame.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` | The libFuzzer entry; returning 0 keeps the run alive, any sanitizer abort is the finding. |
| `FuzzedDataProvider for prefix fields` | Lets the fuzzer mutate configuration and payload independently instead of corrupting both. |
| `-fsanitize=fuzzer,address,undefined` | Combines the engine with the oracles; without ASan a heap overflow may not abort. |
| `afl-cmin for corpus minimisation` | Reduces the corpus to inputs that each add coverage, which keeps campaign startup fast. |

## Worked Contrast

**Harness That Truncates and Hides Errors:**

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char buf[64];
    memcpy(buf, data, size > 64 ? 64 : size);  // BUG: silently truncates, so deep parser states are unreachable
    parse(buf);                                // BUG: return value ignored
    return 0;
}
```

**Length-Preserving Harness With Explicit Bounds:**

```c
#include <stdint.h>
#include <stddef.h>

int parse(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > 1 << 20) {
        return 0;
    }
    (void)parse(data, size);
    return 0;
}
```

**Why this matters:** Copying into a fixed buffer truncates every input at 64 bytes, so the parser can never reach the states where the bug lives, and ignoring the return value hides the error paths the fuzzer is meant to explore. Passing the real length preserves the input and lets sanitizer aborts surface as findings.

## When It Is NOT This Issue

- **Crash from a malformed seed.** A seed that already crashes means the corpus is invalid, not that the campaign found something.
- **Leak reported at exit.** LeakSanitizer fires on library globals; confirm the allocation is reachable from the harness input.
- **Timeout from the harness's own allocation.** A giant input that OOMs the harness is a corpus problem; cap input size.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `LLVMFuzzerTestOneInput` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `libfuzzer-and-afl-harness-engineering` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: libfuzzer-and-afl-harness-engineering
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `LLVMFuzzerTestOneInput`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile libfuzzer_and_afl_harness.py; python libfuzzer_and_afl_harness.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `libfuzzer-and-afl-harness-engineering` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-119, CWE-787`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | cyber-security/security-code (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
