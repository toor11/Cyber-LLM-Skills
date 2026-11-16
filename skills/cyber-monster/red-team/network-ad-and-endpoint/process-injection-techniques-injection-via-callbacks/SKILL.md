---
name: process-injection-techniques-injection-via-callbacks
description: Injection through callback mechanisms. Covers executing payloads through thread pool, window, timer and other callback registrations without explicit remote thread creation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["callback injection", "threadpool injection", "enumwindows callback"]
cwe: [CWE-94]
owasp: []
attack: [T1055]
capec: [CAPEC-242]
related: [process-injection-techniques, process-injection-techniques-classic-and-apc-injection, process-injection-techniques-hollowing-and-stomping, network-recon-and-port-scanning]
parent: process-injection-techniques
corpus_sparse: true
---

# Process Injection Techniques Injection via Callbacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Windows provides many notification mechanisms — thread-pool waits, window-procedure callbacks, `EnumWindows` callbacks, TLS callbacks, vectored exception handlers — and each takes a function pointer that the system will call later. If an attacker can place a pointer to their code in another process's notification structure, the system performs the execution, so no thread is created and no remote thread event fires. The telemetry is correspondingly indirect: the registration API and the resulting execution in a process that never called the code.

- **CWE-269 (Improper Privilege Management):** privilege, delegation or ACL handling lets a principal act outside its intended sphere.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`process-injection-techniques`](../process-injection-techniques/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** no remote thread is created but code runs **THEN** a callback mechanism is the likely route; the registration is the event to look for
3. **IF** the process is a GUI process **THEN** window-procedure and `EnumWindows` callbacks are available; the message queue is the execution trigger
4. **IF** the process is a service or console application **THEN** thread-pool waits and `EnumSystemLocales`-style callbacks are the available mechanisms
5. **IF** the code runs once at load **THEN** a TLS callback is the mechanism, and it runs before the entry point
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `process-injection-techniques-injection-via-callbacks` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The mechanism is a remote thread or APC | [`process-injection-techniques-classic-and-apc-injection`](../process-injection-techniques-classic-and-apc-injection/SKILL.md) | Thread creation |
| The mechanism is a mapped section | [`process-injection-techniques-hollowing-and-stomping`](../process-injection-techniques-hollowing-and-stomping/SKILL.md) | Image replacement |
| Coverage is the question | [`process-injection-techniques`](../process-injection-techniques/SKILL.md) | Telemetry inventory |
| The target is a security product | [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) | Protected process integrity |
| Need the class-level branch table first | [`process-injection-techniques`](../process-injection-techniques/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish whether callback registration is observable.** Kernel callbacks and thread-pool registration produce provider events; without that telemetry, the finding is the coverage gap. That is the honest answer more often than not for this technique.
2. **Look for execution without a corresponding creation.** A process that executes code with no thread or process creation event is the shape. Correlate module loads and network connections with no preceding creation event.
3. **Read the target's notification structures in a memory image.** For an offline investigation, thread-pool wait entries and window procedure pointers that fall outside any module are the artefacts. This is a forensics task and requires an image.
4. **Name the stop condition.** Stop at the first execution-without-creation correlation or the first out-of-module function pointer. Live instrumentation of a production process is invasive.
5. **State the proof.** Proof is the registration event plus the later execution in the target, or the out-of-module function pointer in a memory image with its address. The absence of a thread event alone is not proof of a callback technique.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Execution in a process with no creation event | Proves the code ran via a mechanism other than process or thread creation; Windows with correlated telemetry. |
| Thread-pool wait entry pointing outside every module | Proves a callback registration to foreign code, readable in a memory image; Windows. |
| Window procedure pointer outside every module | Proves a GUI callback hijack, the subclassing mechanism; Windows GUI processes. |
| TLS callback in a module with no corresponding entry in the on-disk file | Proves a load-time callback injection; Windows PE files. |
| Vectored exception handler outside every module | Proves an exception-dispatch hijack, which fires on the next exception; Windows. |

## Worked Contrast

**Weak configuration — no thread-pool or callback telemetry, and no memory-image process analysis:**

```powershell
# the estate collects process creation and network events only;
# a callback-based execution produces neither, so the behaviour is invisible
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} -MaxEvents 3
```

**Hardened configuration — callback-adjacent telemetry and periodic memory-image triage for high-value hosts:**

```powershell
# collect kernel-callback and thread-pool provider events where available,
# and include an unbacked-executable-memory check in the periodic triage
# verification: a benign thread-pool registration produces a provider event
```

**Why this matters:** callback execution avoids the events that process-based detection relies on, so the control is additional telemetry plus memory triage, verified by a benign registration producing an event.

## When It Is NOT This Issue

- **A thread-pool callback in a legitimate application.** Thread pools are the standard Windows concurrency mechanism; the finding requires the callback to point outside a module.
- **A TLS callback in a signed binary.** Legitimate runtimes use TLS callbacks; check the module's signature and its on-disk entry.
- **An exception handler in a runtime.** .NET and C++ runtimes install handlers; they resolve inside a mapped module.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `process-injection-techniques-injection-via-callbacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `process-injection-techniques-injection-via-callbacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: process-injection-techniques-injection-via-callbacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-94 | Mapping: T1055]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) - Blue Detection/Defense Counterpart
- [`process-injection-techniques`](../process-injection-techniques/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`process-injection-techniques-classic-and-apc-injection`](../process-injection-techniques-classic-and-apc-injection/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`process-injection-techniques-hollowing-and-stomping`](../process-injection-techniques-hollowing-and-stomping/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `process-injection-techniques-injection-via-callbacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-94, T1055`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
