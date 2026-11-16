---
name: edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion
description: ETW and telemetry evasion. Covers patching ETW providers, .NET and PowerShell telemetry suppression, and the detection signals each eviction produces. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["etw patch", "etw bypass", "powershell logging bypass", "telemetry evasion"]
cwe: [CWE-693]
owasp: []
attack: [T1562]
capec: [CAPEC-578]
related: [edr-evasion-and-amsi-bypass, edr-evasion-and-amsi-bypass-amsi-bypass, edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls, edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection]
parent: edr-evasion-and-amsi-bypass
---

# EDR Evasion and AMSI Bypass Etw and Telemetry Evasion - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md)

## Mechanism and Preconditions

ETW is the kernel-mediated event pipeline that most Windows telemetry depends on, including Sysmon, Defender, PowerShell logging and EDR behavioural rules. Providers write to sessions, sessions are consumed by a logger, and a process can affect its own contribution by patching the user-mode write function or by disabling the session. The control is that consumer-side collection and kernel-side providers are independent of the producing process, which is why suppressing a user-mode write is detectable as a gap rather than a success.

- **CWE-693 (Protection Mechanism Failure):** The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** a specific provider stops reporting for one process **THEN** that is a user-mode write suppression, visible as a gap for that process only
3. **IF** an entire session stops **THEN** that is a session or consumer change, which needs administrative rights and leaves a log
4. **IF** telemetry is missing on one host but present elsewhere **THEN** that is the strongest signal; compare the host's channel record counts against peers
5. **IF** the EDR agent is the target **THEN** that is process termination or tampering rather than ETW suppression; use the driver and unhooking skills
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Script scanning rather than telemetry | [`edr-evasion-and-amsi-bypass-amsi-bypass`](../edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md) | AMSI interface |
| User-mode API hooks | [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) | Hook integrity |
| Kernel driver tampering | [`byovd-and-driver-abuse`](../byovd-and-driver-abuse/SKILL.md) | Process termination and callback removal |
| Log clearing at the event log rather than the pipeline | [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) | Event log manipulation |
| Need the class-level branch table first | [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory the sessions and consumers.** `logman query -ets` lists active sessions; the Sysmon and Defender channels show consumer state. Record the counts, because a gap is only visible against a baseline.
2. **Read the provider enablement for the channels that matter.** PowerShell, Defender, Sysmon and the EDR's own provider. A channel that is enabled but receiving nothing for a host that is otherwise active is the anomaly.
3. **Establish the gap differential across hosts.** Compare record counts per channel across a peer group for the same period. A single host with a materially lower count is the finding, and the comparison is more reliable than any single event.
4. **Name the stop condition and the safety rule.** Stop at the first proven gap. Do not stop a logging service on a production host, and do not leave a patched in-memory region.
5. **State the proof.** Proof is the session and provider inventory plus the cross-host record-count comparison for a fixed window. A tool that reports success without a measurable gap has proven nothing.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Active ETW session list from `logman -ets` | Proves which sessions exist, and a missing expected session proves a consumer change; Windows. |
| Per-channel record count for a fixed window | Proves a host-level gap when compared with peers, which is the most reliable suppression signal; Windows. |
| Sysmon event 8 for thread creation in a telemetry host process | Proves an injection attempt against the logging process; Windows with Sysmon. |
| Windows Security 1100 for the event logging service stopping | Proves the local logging service changed state, which affects every channel; Windows. |
| ETW provider enablement for `Microsoft-Windows-Kernel-Process` | Proves whether process-creation telemetry exists at the provider level, independent of the consumer; Windows. |

## Worked Contrast

**Weak configuration — logging service can be stopped by a local administrator with no alerting on the state change:**

```powershell
Get-Service EventLog | Select-Object Status,StartType
# StartType Manual and no alert on event 1100: an administrator can stop the
# service, and the resulting gap is only visible days later in a report
```

**Hardened configuration — logging service protected and its state change alerted in real time:**

```powershell
Set-Service EventLog -StartupType Automatic
# plus: alert on Security 1100/1102 and System 7034/7035 in the SIEM with a
# forwarding latency budget shorter than the gap you want to detect
# verification: stopping the service produces an alert within the latency budget
```

**Why this matters:** suppression is only useful if the gap goes unnoticed, so the controls are the service state and a real-time alert on its change, verified by triggering the alert.

## When It Is NOT This Issue

- **A host with genuinely low activity.** A idle server produces few events; compare against peers in the same role before calling it a gap.
- **A channel that is disabled by design.** Some channels are off in the base image; check the build baseline rather than treating absence as tampering.
- **Forwarding latency.** A collector backlog delays events without any suppression; compare timestamps against the collector's own queue depth.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion
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
- [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](../edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693, T1562`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/github_security_md (3), CYBER_CPT/sigmahq (2), CYBER_CPT/heresecurity (2), CYBER_CPT/oxdf (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
