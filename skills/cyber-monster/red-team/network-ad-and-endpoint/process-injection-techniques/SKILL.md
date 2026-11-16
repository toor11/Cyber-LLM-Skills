---
name: process-injection-techniques
description: "Injects code into other processes: classic remote threads, APC injection, process hollowing, module stomping, thread hijacking and callback-based execution, with detection tradeoffs for each. Use after gaining execution on a Windows host."
family: network-ad-and-endpoint
tier: core
triggers: ["process injection", "process hollowing", "apc injection", "thread hijacking", "shellcode injection"]
cwe: [CWE-94]
owasp: []
attack: [T1055]
capec: [CAPEC-242]
related: [process-injection-techniques-classic-and-apc-injection, process-injection-techniques-hollowing-and-stomping, process-injection-techniques-injection-via-callbacks, network-recon-and-port-scanning]
---

# Process Injection Techniques - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md)

## Mechanism and Preconditions

Process injection is any technique that makes code execute inside another process's address space, and its purpose is to borrow that process's identity — its token, its loaded modules, its reputation. The mechanisms differ (remote thread creation, section mapping, APC queuing, thread execution hijacking, callback-based execution) but they converge on the same observable sequence: a handle to another process with write access, an allocation, a write, and then a way to make the target execute. That sequence is what telemetry records, which is why the technique is a detection-engineering problem rather than a payload problem.

- **CWE-269 (Improper Privilege Management):** privilege, delegation or ACL handling lets a principal act outside its intended sphere.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is a user-mode remote thread **THEN** use [`process-injection-techniques-classic-and-apc-injection`](../process-injection-techniques-classic-and-apc-injection/SKILL.md)
2. **IF** the target is a mapped section or a hollowed image **THEN** use [`process-injection-techniques-hollowing-and-stomping`](../process-injection-techniques-hollowing-and-stomping/SKILL.md)
3. **IF** the target is a callback or a thread pool **THEN** use [`process-injection-techniques-injection-via-callbacks`](../process-injection-techniques-injection-via-callbacks/SKILL.md)
4. **IF** the objective is to suppress a security product **THEN** that is EDR tampering; pair with [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `process-injection-techniques` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Remote thread and APC queuing | [`process-injection-techniques-classic-and-apc-injection`](../process-injection-techniques-classic-and-apc-injection/SKILL.md) | Thread creation semantics |
| Section mapping and image hollowing | [`process-injection-techniques-hollowing-and-stomping`](../process-injection-techniques-hollowing-and-stomping/SKILL.md) | Mapping rather than writing |
| Callback and thread-pool execution | [`process-injection-techniques-injection-via-callbacks`](../process-injection-techniques-injection-via-callbacks/SKILL.md) | Notification registration |
| The injected code targets a security product | [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) | Telemetry integrity |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish whether the telemetry covers the sequence.** Sysmon events 8, 10 and 25 cover thread creation, process access and image tampering; kernel callbacks cover allocation and protection changes. If none of that telemetry exists, the finding is the coverage gap, not the technique.
2. **Map the mechanism to its observable events.** Remote thread: 8 with `CreateRemoteThread` and 10 with a write-access mask. Mapping: 25 for image tampering plus a remote allocation. APC: 8 with `QueueUserAPC` context. Callback: a registration event and an unusual execution context.
3. **Baseline the sanctioned cross-process access in the estate.** EDR, backup, accessibility tools and debuggers all open other processes with broad masks. The differential is a source process whose baseline includes no cross-process access.
4. **Name the stop condition and the safety rule.** Stop at the first proven coverage gap or the first unexplained access pair. Injecting into a production process is a state change that can crash it and is never required to report the exposure.
5. **State the proof.** Proof is the event pair: a handle request with a write mask on one process, followed by a thread or APC creation in the same target. Either event alone has legitimate explanations; the pair is the finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Sysmon event 10 with `GrantedAccess` including `0x1F0FFF` or `0x0008` | Proves a write-capable handle to another process, the injection precondition; Windows with Sysmon. |
| Sysmon event 8 with `CreateRemoteThread` | Proves a thread created in another process, the classic mechanism; Windows with Sysmon. |
| Sysmon event 25 for image tampering | Proves a mapped image was modified, the hollowing or stomping mechanism; Windows with Sysmon 12 or later. |
| Allocation with `PAGE_EXECUTE_READWRITE` in another process | Proves an executable region was created remotely, which legitimate software rarely does; Windows with kernel telemetry. |
| Cross-process access from a source with no baseline | Proves the access is anomalous for that process, which is the strongest filter on a noisy event class; Windows. |

## Worked Contrast

**Weak configuration — no Sysmon, no cross-process access auditing, and no EDR behavioural rules:**

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
# absent: no event 8, 10 or 25, and object access auditing for process objects is off,
# so a remote thread creation produces no record anywhere
```

**Hardened configuration — Sysmon with the injection-relevant events, and process-object auditing on critical hosts:**

```powershell
# deploy a maintained Sysmon configuration covering events 8, 10 and 25
# enable 'Audit Handle Manipulation' where object access auditing is used
# verification: a benign cross-process access produces event 10 with its GrantedAccess mask
```

**Why this matters:** injection is invisible without process-object telemetry, so the control is the telemetry configuration and the verification is an event appearing for a known-benign access.

## When It Is NOT This Issue

- **Broad cross-process access from a security product.** EDR and backup agents open processes with full access routinely; the baseline excludes them.
- **A debugger or accessibility tool.** These are designed to attach; check the image signature and the user context.
- **A single event without its pair.** A handle request with no subsequent thread creation has many benign explanations; report the pair or nothing.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `process-injection-techniques` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `process-injection-techniques` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: process-injection-techniques
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-94 | Mapping: T1055]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) - Blue Detection/Defense Counterpart
- [`process-injection-techniques-classic-and-apc-injection`](../process-injection-techniques-classic-and-apc-injection/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`process-injection-techniques-hollowing-and-stomping`](../process-injection-techniques-hollowing-and-stomping/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`process-injection-techniques-injection-via-callbacks`](../process-injection-techniques-injection-via-callbacks/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `process-injection-techniques` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-94, T1055`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 27 |
| Distinct dataset sources | 10 |
| Top sources | CYBER_CPT/atomic_red_team (7), CYBER_CPT/sigmahq (4), cyber-security/CyberSec-Dataset (3), CYBER_CPT/osv (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 12 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
