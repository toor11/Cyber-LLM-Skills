---
name: edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls
description: Userland unhooking and direct syscalls. Covers restoring hooked ntdll sections, direct and indirect syscall stubs, and the tradeoffs against modern kernel telemetry. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["unhooking", "direct syscall", "indirect syscall", "ntdll unhook"]
cwe: [CWE-693]
owasp: []
attack: [T1562]
capec: [CAPEC-578]
related: [edr-evasion-and-amsi-bypass, edr-evasion-and-amsi-bypass-amsi-bypass, edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion, edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection]
parent: edr-evasion-and-amsi-bypass
---

# EDR Evasion and AMSI Bypass Unhooking and Direct Syscalls - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md)

## Mechanism and Preconditions

User-mode API hooking works by redirecting the first instructions of a function in a loaded DLL to a product's inspection code. Because the hook lives in the process's own address space, a process can restore the original bytes from a clean copy of the DLL, or bypass the hooked function entirely by issuing the system call directly. The control is that the product also observes kernel-side transitions, so a direct system call still produces the kernel callback the product relies on — which makes the technique a detection-evasion attempt rather than a detection bypass.

- **CWE-693 (Protection Mechanism Failure):** The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the target is user-mode hook integrity **THEN** read the in-memory bytes of a hooked function against the on-disk copy; that comparison is the evidence
3. **IF** the target is a direct system call **THEN** the kernel callback still fires, so the finding is which telemetry survived
4. **IF** the question is whether the product hooks at all **THEN** an unhooked process is not evidence of evasion; some products rely on kernel callbacks only
5. **IF** the process must be protected **THEN** check PPL and process protection level before concluding the memory can be altered
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Telemetry suppression rather than hook removal | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | Event pipeline |
| Script scanning | [`edr-evasion-and-amsi-bypass-amsi-bypass`](../edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md) | AMSI interface |
| Kernel-level tampering through a driver | [`byovd-and-driver-abuse`](../byovd-and-driver-abuse/SKILL.md) | Callback removal |
| Process injection as the delivery vehicle | [`process-injection-techniques`](../process-injection-techniques/SKILL.md) | Injection telemetry |
| Need the class-level branch table first | [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish whether hooks exist and where.** Compare the in-memory first bytes of `NtCreateFile`, `NtAllocateVirtualMemory` and `NtWriteVirtualMemory` against the on-disk `ntdll.dll` copy. A jump instruction where the disk copy has a `mov` is a hook. That comparison is non-destructive and is the primary evidence.
2. **Map which products hook and which rely on kernel callbacks.** Some EDR products hook user-mode functions; others rely on kernel callbacks and ETW only. A process with no hooks in a kernel-callback product has not evaded anything.
3. **Read the process protection level.** PPL and process protection decide whether the memory can be modified at all. A protected process cannot be unhooked from user mode, which closes the technique.
4. **Name the stop condition and the safety rule.** Stop at the first hook-state comparison. Restoring bytes in a production process is a state change that can crash it, and it is never required for a report.
5. **State the proof.** Proof is the byte comparison, the product's hooking model, and the process protection level. The absence of an alert after a direct system call is not proof of evasion unless the kernel-callback telemetry is also shown to be missing.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `mov edi, edi` overwritten by a jump in memory | Proves a user-mode hook exists on that function, which is the baseline for the comparison; Windows. |
| In-memory `ntdll` bytes matching the on-disk copy for a hooked function | Proves the hook was removed or was never present, which is the differential; Windows. |
| Process protection level of the calling process | Proves whether its own memory can be modified, which bounds the technique; Windows with PPL. |
| Sysmon event 10 for a process opening its own image with write access | Proves an in-memory modification attempt, which is the behaviour to detect; Windows. |
| Direct system call stub without a `ntdll` transition | Proves the API layer was skipped, and the kernel callback is then the only remaining telemetry; Windows x64. |

## Worked Contrast

**Weak configuration — sensor relies only on user-mode hooks and runs unprotected:**

```powershell
Get-Process -Name 'edragent' | Select-Object Name,ProtectionLevel
# ProtectionLevel empty: the agent has no PPL, so its hooks in any process can be
# restored from the on-disk ntdll copy without any kernel interaction
```

**Hardened configuration — sensor protected and kernel callbacks enabled alongside hooks:**

```powershell
# vendor configuration: enable the early-launch anti-malware driver, the
# kernel callback registration, and process protection for the agent
# verification: the agent reports a protection level and a direct-syscall probe still produces an alert
```

**Why this matters:** hook removal only defeats a hook-only sensor, so the control is kernel-side observation plus process protection, and the verification is an alert surviving a direct system call.

## When It Is NOT This Issue

- **A function with no hook in a product that uses kernel callbacks.** Absence of user-mode hooks is a product design choice, not a gap.
- **A hook-shaped byte sequence from a legitimate hotfix.** Some Windows updates install hotfix shims in `ntdll`; compare against the same build's disk copy before reporting.
- **A protected process with unreadable memory.** A read failure on a PPL process is the protection working, not evidence of tampering.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: T1562]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) - Blue Detection/Defense Counterpart
- [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`edr-evasion-and-amsi-bypass-amsi-bypass`](../edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](../edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693, T1562`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/github_security_md (3), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
