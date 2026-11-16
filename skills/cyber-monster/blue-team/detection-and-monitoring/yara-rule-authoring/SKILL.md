---
name: yara-rule-authoring
description: "Writes and validates YARA rules for files and memory: string selection, modifiers, condition design and false-positive control. Use when creating signatures for malware or suspicious content."
family: detection-and-monitoring
tier: core
triggers: ["yara rule", "yara authoring", "write yara", "yara signature"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, siem-query-and-log-analysis, log-source-onboarding-and-parsing]
---

# Yara Rule Authoring - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

A YARA rule is a boolean predicate over bytes plus an optional module evaluation, and its quality is decided by two properties that no compiler can check: *robustness* (can the adversary change the artefact cheaply?) and *precision* (how often does the same predicate match benign files?). String selection sets robustness — a filename or a hash is trivially changed, whereas a compiled-in algorithm or an unusual API sequence is expensive to remove. Condition design sets precision — a bare `any of them` over common library strings matches half a filesystem. Text strings in compiled code must be `ascii wide` with `fullword` where the boundary is meaningful, because the compiler emits UTF-16LE; hex strings with `??` wildcards tolerate register substitution; and `pe` module checks add structural context that survives string edits. YARA-X, the Rust rewrite now shipping as `yr`, is stricter than legacy YARA: it rejects constructs that previously compiled, exposes int64/uint64 built-ins, and reports matches as text, `ndjson` or `json`.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is a compiled Windows binary **THEN** emit `ascii wide` (and `fullword` where boundaries matter); **IF** it is a script or document **THEN** plain `ascii` with `nocase` is usually right, and `wide` only adds noise.
2. **IF** the rule keys on a filename, a hash, or a single API name **THEN** treat it as low-robustness by construction and add a structural condition; **IF** it keys on an algorithm constant or an unusual call sequence **THEN** it is robust but must be checked for precision.
3. **IF** the engine is YARA-X **THEN** validate with the `yr` CLI and expect stricter compile errors than legacy `yara` accepted; **IF** the fleet still runs legacy YARA **THEN** test on both before shipping.
4. **IF** the rule must distinguish families **THEN** combine at least one code-level string with one structural check (`pe.imphash`, section entropy, `pe.number_of_sections`); a single string cannot separate a family from its builder kit.
5. **IF** the scan target is memory or a process image **THEN** expect paged-out content to be absent and label the result partial; a negative memory scan is not evidence the code never ran.
6. **IF** telemetry source covering `strings` or `condition` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need validation, precision and scan queries | [`QUERIES.md`](QUERIES.md) | Compile, corpus and memory classes |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | `yr scan`, `yr compile`, output formats, threading |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Scan scope, quarantine and verification |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Scanner engineering rather than rule authoring | [`yara-and-yara-x-scanner-engineering`](../../security-automation-and-tool-development/yara-and-yara-x-scanner-engineering/SKILL.md) | Owned there: pipeline integration and fleet deployment |
| Behavioural rather than byte-level detection | [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) | Different artefact and different failure modes |

## Procedure

1. **Confirm the evidence source and the engine before writing strings.** Establish which engine will evaluate the rule (`yr` versus legacy `yara`) and which artefacts are available (on-disk files, memory images, extracted payloads). A rule written for a packed on-disk sample matches nothing in memory, where the unpacked image lives.
2. **Choose the branch: string-anchored, structure-anchored, or hybrid.** String-anchored rules are fast and brittle; structure-anchored rules (PE characteristics, section layout, entropy) survive strings edits but drift across versions; hybrid rules pair one of each. Say which you chose, because it defines what an evasion costs the adversary.
3. **Define the baseline-versus-probe differential against a benign corpus.** Compile the rule and scan a clean corpus — a system directory, an installer cache, a known-good build artefact set — and count hits per rule. Then scan the positive sample set. The finding is the ratio between the two, per rule identifier.
4. **Name the stop condition.** Stop when the engine rejects the construct, when the only distinguishing strings are shared with a common framework or runtime, when the sample is packed and the strings you can see belong to the packer, when the benign corpus is too small to measure precision, or when the scan target is memory and the region may be paged out.
5. **State what counts as proof.** Proof is a rule that matches every sample in the positive set, matches nothing in the benign corpus above an agreed threshold, and compiles under the engine the fleet actually runs. A rule that matches the sample but also matches a system binary has proven its specificity is absent.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| `yr check` exit status | compile | The rule is valid under the stricter engine before it reaches a scanner |
| Hit count per rule on a benign corpus | precision | Whether the predicate is specific enough to be actionable at fleet scale |
| Hit set over the positive samples | robustness | That the rule covers the family rather than one build of it |
| `ascii wide` versus `ascii` match locations | string design | Whether the string is actually emitted as UTF-16LE in the compiled artefact |
| `pe.imphash` or section-count condition | structure | Family-level similarity that survives string edits |
| Match offsets and matched-string identifiers in `ndjson` output | triage | Which part of the rule fired, so a false positive can be attributed to one string rather than the whole rule |
| Memory scan of a known-running process | memory | Whether unpacked code is reachable, and whether paging makes the negative unproven |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```yaml
rule Suspicious_Loader
{
  strings:
    $a = "VirtualAlloc"
    $b = "LoadLibrary"
    $c = "GetProcAddress"
  condition:
    any of them
}
// These three names appear in a great many legitimate binaries and in the
// import table of anything that loads plugins. No width handling, no PE
// context, no benign-corpus measurement, and 'any of them' makes it worse.
```

**High-Signal Grounded Detection:**

```yaml
rule Loader_Sleep_Then_Execute
{
  meta:
    description = "Loader that allocates, sleeps, then transfers to the allocation"
    robustness = "hybrid: import pair plus allocation-then-sleep ordering"
  strings:
    $sleep  = "Sleep" ascii wide fullword
    $valloc = "VirtualAlloc" ascii wide fullword
    $vprot  = "VirtualProtect" ascii wide fullword
    $marker = { 4D 5A ?? ?? ?? ?? ?? ?? 50 45 00 00 }   // embedded PE header
  condition:
    uint16(0) == 0x5A4D
    and pe.number_of_sections <= 5
    and 2 of ($sleep, $valloc, $vprot)
    and $marker
    and filesize < 2MB
}
// Structural gate (valid PE, small section count) plus the ordering-relevant
// import set plus an embedded-PE marker. Test against a benign corpus before
// shipping: the import pair alone is common in installers.
```

**Why this matters:** the weak rule matches any binary that links three extremely common APIs and gives the analyst no way to explain a hit. The strong rule gates on structure so non-PE blobs are excluded, requires a combination rather than a single string, and states in `meta` which part is robust and which part needs corpus measurement.

## When It Is NOT This Issue

- **Packed samples:** the visible strings belong to the packer, so a rule built from them matches the builder kit rather than the payload. The unpacked image is the target, and it is not on disk.
- **Shared runtime strings:** Python, .NET and Go binaries embed runtime and library strings in enormous quantities. A rule keyed on any of them matches every application built with that runtime.
- **Legitimate dual-use tooling:** remote administration, debugging and installer frameworks import the same APIs a loader does. The rule needs ordering or an embedded-payload marker, not a longer import list.
- **Memory scans with paged-out regions:** a process image with pages on disk will not match, and the negative says nothing about whether the code executed.
- **Cross-engine portability:** a rule that compiles under legacy YARA may be rejected by YARA-X, and a rule using newer built-ins will not run on legacy. Test on the engine the fleet actually deploys.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER invent YARA module fields, built-in functions or CLI flags** — confirm them against the engine version you will deploy to.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `strings` was disabled, rotated out, or uncollected.**
- **NEVER present a rule that matches the sample as validated** — a benign-corpus run is required to claim specificity.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the engine version and the artefact type (on-disk, extracted, memory image) were established before string selection.
- [ ] **Branch chosen:** string-anchored, structure-anchored or hybrid was selected and stated, with its evasion cost described.
- [ ] **Differential defined:** the compiled rule was scanned against a benign corpus and the positive set, and the per-rule ratio is reported.
- [ ] **Stop condition stated:** engine rejection, shared-runtime strings, packing, undersized benign corpus or paged-out memory was named where it applied.
- [ ] **Proof standard met:** the rule matches the positive set, stays under the agreed benign threshold, and compiles on the deployed engine.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: yara-rule-authoring
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)
- [`alert-tuning-and-false-positive-reduction`](../alert-tuning-and-false-positive-reduction/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Robustness and precision are separate questions:** a rule can be hard to evade and still match everything. Measure both, and say which one you measured.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; scanning read-only copies and quarantining to a holding area are safe, deleting artefacts is not.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 19 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/L5/ctf_search (7), OffsecCyber (3), cyber-security/CyberSec-Dataset (3), CYBER_CPT/awesome_list (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
