---
name: process-injection-techniques-hollowing-and-stomping
description: Process hollowing and module stomping. Covers hollowing a legitimate process and stomping a loaded module to run payloads from backed memory. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["process hollowing", "module stomping", "process doppelganging"]
cwe: [CWE-94]
owasp: []
attack: [T1055]
capec: [CAPEC-242]
related: [process-injection-techniques, process-injection-techniques-classic-and-apc-injection, process-injection-techniques-injection-via-callbacks, network-recon-and-port-scanning]
parent: process-injection-techniques
---

# Process Injection Techniques Hollowing and Stomping - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md)

## Mechanism and Preconditions

Hollowing creates a process in a suspended state, replaces its image with different content, and resumes it, so the process's identity is the original binary while the executing code is not. Stomping modifies a loaded module's mapped image in place, which leaves the on-disk file untouched and defeats hash-based verification. Both attack the correspondence between a process and its backing file, so the detectable property is that correspondence breaking: an image whose in-memory bytes do not match the file on disk, or a thread whose start address is not in any mapped module.

- **CWE-269 (Improper Privilege Management):** privilege, delegation or ACL handling lets a principal act outside its intended sphere.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`process-injection-techniques`](../process-injection-techniques/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** a process's memory does not match its file **THEN** that is the core finding; Sysmon event 25 or a memory-versus-disk comparison proves it
3. **IF** a thread's start address is unbacked **THEN** it points outside every mapped module, which is the stomping and shellcode signature
4. **IF** the process was created suspended **THEN** creation followed by a long pause before the first thread activity is the hollowing shape
5. **IF** the binary on disk is legitimate and signed **THEN** that is expected for hollowing, which is why signature checks alone do not detect it
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `process-injection-techniques-hollowing-and-stomping` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The mechanism is a remote thread | [`process-injection-techniques-classic-and-apc-injection`](../process-injection-techniques-classic-and-apc-injection/SKILL.md) | Thread creation |
| The mechanism is a callback | [`process-injection-techniques-injection-via-callbacks`](../process-injection-techniques-injection-via-callbacks/SKILL.md) | Notification registration |
| The question is module integrity generally | [`process-injection-techniques`](../process-injection-techniques/SKILL.md) | Telemetry inventory |
| The target is a security product | [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) | Protected process integrity |
| Need the class-level branch table first | [`process-injection-techniques`](../process-injection-techniques/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish whether image-tampering telemetry exists.** Sysmon event 25 reports a mapped image change; without it, the finding depends on memory-versus-disk comparison, which needs a live tool or a memory image.
2. **Compare in-memory module bytes against the on-disk file.** For a suspect process, hash each mapped module's memory region and compare with the file's hash. A mismatch is proof, and the specific module names the technique.
3. **Read thread start addresses against the module map.** A start address outside every mapped range proves unbacked executable memory, which is the shellcode and stomping signature regardless of how it got there.
4. **Name the stop condition.** Stop at the first mismatch or unbacked thread. Memory forensics on a production host is invasive; capture the evidence and stop.
5. **State the proof.** Proof is the module name with its memory hash and disk hash, or the thread id with its start address and the absence of a containing module. A process name alone is never proof.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Sysmon event 25 for image tampering | Proves a mapped image was modified, with the region's base address and size; Windows with Sysmon 12 or later. |
| Thread start address outside every module | Proves unbacked executable memory, the shellcode signature; Windows with memory forensics or EDR telemetry. |
| Process created suspended with a long pause before first thread | Proves the hollowing sequence, where creation and execution are separated; Windows with process-creation and thread telemetry. |
| Memory hash differing from disk hash for a system module | Proves stomping of that module, which signature verification cannot catch; Windows with memory comparison. |
| `PAGE_EXECUTE_READWRITE` region not backed by a file | Proves an anonymous executable region, which legitimate code loading rarely produces; Windows with kernel telemetry. |

## Worked Contrast

**Weak configuration — no image-tampering telemetry and no memory integrity checking:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=25} -MaxEvents 1
# no event 25 and no periodic module-hash comparison: a stomped module is
# indistinguishable from a clean one using file-based checks
```

**Hardened configuration — image-tampering events collected and module hashes compared periodically:**

```powershell
# Sysmon: enable the ImageTampering event (25) in the configuration
# and schedule a module-hash comparison for high-value processes
# verification: a benign patch to a test process produces event 25 with the region
```

**Why this matters:** hollowing and stomping break the process-to-file correspondence, so the control is telemetry that reports that break, verified by an event for a known modification.

## When It Is NOT This Issue

- **A just-in-time compiled region.** .NET and JIT engines create executable memory legitimately; the module map usually accounts for it.
- **A hot-patched system function.** Windows hotpatching modifies in-memory code by design; compare against the same build's baseline.
- **A packed legitimate installer.** Some installers unpack into memory; the signature on the parent and the install context matter.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `process-injection-techniques-hollowing-and-stomping` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `process-injection-techniques-hollowing-and-stomping` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: process-injection-techniques-hollowing-and-stomping
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
- [`process-injection-techniques-injection-via-callbacks`](../process-injection-techniques-injection-via-callbacks/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `process-injection-techniques-hollowing-and-stomping` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-94, T1055`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/github_security_md (3), cyber-security/vulnerability-intelligence__mitre-attack-techniques.json (1), CYBER_CPT/atomic_red_team (1), CYBER_CPT/ired_team (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
