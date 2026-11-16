---
name: process-injection-techniques-classic-and-apc-injection
description: Classic thread and APC injection. Covers remote thread creation, APC queueing, thread hijacking and section-based injection with reliability and detection tradeoffs. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["createremotethread", "apc injection", "thread hijacking", "section injection"]
cwe: [CWE-94]
owasp: []
attack: [T1055]
capec: [CAPEC-242]
related: [process-injection-techniques, process-injection-techniques-hollowing-and-stomping, process-injection-techniques-injection-via-callbacks, network-recon-and-port-scanning]
parent: process-injection-techniques
---

# Process Injection Techniques Classic and Apc Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md)

## Mechanism and Preconditions

Classic injection writes code into a remote process and starts it with `CreateRemoteThread`; APC injection queues the code to an existing thread and relies on the thread entering an alertable wait. Both need a write-capable handle, an allocation and a write, and both differ only in the final step that causes execution. The final step is the discriminating event, so the methodology pairs the access with the specific execution mechanism rather than treating any cross-process write as injection.

- **CWE-269 (Improper Privilege Management):** privilege, delegation or ACL handling lets a principal act outside its intended sphere.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`process-injection-techniques`](../process-injection-techniques/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the target process is unknown **THEN** APC injection needs a thread in an alertable state, which most interactive processes have; remote thread creation works on any process
3. **IF** the process must not gain a new thread **THEN** APC queuing avoids thread creation, which is why it evades thread-count heuristics
4. **IF** the injection is detected by access events only **THEN** the pair with event 8 is the confirmation; access alone is common
5. **IF** the target is a security product **THEN** that is tampering with a protected process, which PPL blocks; see the evasion skills
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `process-injection-techniques-classic-and-apc-injection` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The mechanism is mapping rather than writing | [`process-injection-techniques-hollowing-and-stomping`](../process-injection-techniques-hollowing-and-stomping/SKILL.md) | Section mapping |
| The mechanism is a callback | [`process-injection-techniques-injection-via-callbacks`](../process-injection-techniques-injection-via-callbacks/SKILL.md) | Notification registration |
| The objective is telemetry suppression | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | Pipeline rather than process |
| Coverage is the question | [`process-injection-techniques`](../process-injection-techniques/SKILL.md) | Telemetry inventory |
| Need the class-level branch table first | [`process-injection-techniques`](../process-injection-techniques/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the execution step the mechanism uses.** `CreateRemoteThread` produces Sysmon event 8 with its `StartAddress`; `QueueUserAPC` also produces event 8 but with a thread that already exists. The distinction is in the event's source thread, so read it rather than assuming.
2. **Confirm the prerequisite access.** A handle with `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION` to the target is required by both mechanisms. That access is event 10, and it is the more reliable of the two to detect because allocation and writing must follow.
3. **Baseline legitimate remote thread creation.** Debuggers, profilers and some accessibility tools create remote threads. The differential is a source image whose baseline contains none, or a target that is not a debugging subject.
4. **Name the stop condition and the safety rule.** Stop at the first access-and-execution pair. Injecting into a production process risks a crash and is never needed to report the exposure.
5. **State the proof.** Proof is event 10 with a write mask followed by event 8 in the same target, with the source image named. The allocation and write events strengthen it but are not always collected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Sysmon 8 `CreateRemoteThread` with `SourceImage` differing from `TargetImage` | Proves cross-process execution, the classic mechanism; Windows with Sysmon. |
| Sysmon 8 with an existing thread id and an APC-like start address | Proves APC queuing rather than new-thread creation; Windows with Sysmon. |
| Sysmon 10 write mask followed by Sysmon 8 in the same target | Proves the access-execution pair, which is the finding; Windows with Sysmon. |
| `PAGE_EXECUTE_READWRITE` allocation in a remote process | Proves an executable region was created remotely, which legitimate software rarely does; Windows with kernel telemetry. |
| Source image with an empty cross-process baseline | Proves the access is anomalous for that process, the strongest available filter; Windows. |

## Worked Contrast

**Weak configuration — Sysmon configured for process creation only, so the access-execution pair is unrecorded:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} -MaxEvents 5
# only event 1 is collected: no process-access and no thread-creation events,
# so remote thread creation leaves no record
```

**Hardened configuration — Sysmon events 8 and 10 collected with the standard configuration:**

```powershell
# deploy a maintained Sysmon configuration including:
#   ProcessAccess (10) with GrantedAccess filters
#   CreateRemoteThread (8)
# verification: a benign debugger attach produces event 10 and event 8 for the same target
```

**Why this matters:** the mechanism is only observable through the access and thread events, so the control is the telemetry configuration and the verification is the pair appearing for a known-benign attach.

## When It Is NOT This Issue

- **A debugger attaching to a process.** Debuggers create remote threads by design; check the image signature and the user context.
- **A cross-process access with a read-only mask.** Reading another process's memory is common and does not enable execution.
- **A single event 8 with the same source and target image.** Self-thread creation is normal runtime behaviour.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `process-injection-techniques-classic-and-apc-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `process-injection-techniques-classic-and-apc-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: process-injection-techniques-classic-and-apc-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-94 | Mapping: T1055]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) - Blue Detection/Defense Counterpart
- [`process-injection-techniques`](../process-injection-techniques/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`process-injection-techniques-hollowing-and-stomping`](../process-injection-techniques-hollowing-and-stomping/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`process-injection-techniques-injection-via-callbacks`](../process-injection-techniques-injection-via-callbacks/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `process-injection-techniques-classic-and-apc-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-94, T1055`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/github_security_md (2), CYBER_CPT/hacktricks (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
