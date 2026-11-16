---
name: edr-evasion-and-amsi-bypass-amsi-bypass
description: AMSI bypass. Covers AMSI architecture, in-memory patching of amsiScanBuffer, provider removal and script-level bypasses, with detection notes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["amsi bypass", "amsiscanbuffer patch", "amsi evasion"]
cwe: [CWE-693]
owasp: []
attack: [T1562]
capec: [CAPEC-578]
related: [edr-evasion-and-amsi-bypass, edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion, edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls, edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection]
parent: edr-evasion-and-amsi-bypass
---

# EDR Evasion and AMSI Bypass AMSI Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md)

## Mechanism and Preconditions

AMSI is a broker: a script host submits content to whichever providers are registered, and each provider returns a verdict. The interface is a user-mode DLL (`amsi.dll`) loaded into the calling process, so the integrity of that process's view of `amsi.dll` is the entire control. If the script host can be made to load a different `amsi.dll`, or if the in-memory `AmsiScanBuffer` can be altered before the call, the provider never sees the content. The corresponding defence is that the scan result is reported through ETW and Defender rather than only through the return value.

- **CWE-693 (Protection Mechanism Failure):** The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the script host loads `amsi.dll` from `System32` **THEN** the normal case; the question becomes whether the in-memory function is intact
3. **IF** a process loads `amsi.dll` from another path **THEN** that is a DLL search-order finding, which is the durable condition worth reporting
4. **IF** the provider list is empty **THEN** no script content is inspected at all; that is a configuration gap rather than a bypass
5. **IF** the script content is machine-generated obfuscation **THEN** the decoded text in event 4104 is the evidence; the obfuscation itself is not a finding
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `edr-evasion-and-amsi-bypass-amsi-bypass` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Telemetry is the surface | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | Event loss rather than scan bypass |
| User-mode hooks are the surface | [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) | API integrity |
| Content obfuscation rather than scan bypass | [`antivirus-evasion-and-obfuscation`](../antivirus-evasion-and-obfuscation/SKILL.md) | Encoding and packing |
| The driver path is the route | [`byovd-and-driver-abuse`](../byovd-and-driver-abuse/SKILL.md) | Kernel-level tampering |
| Need the class-level branch table first | [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the provider registration and the DLL path.** `HKLM\SOFTWARE\Microsoft\AMSI\Providers` lists providers; the loaded module's path in a script host tells you whether the real DLL is in use. Both reads are non-destructive and answer most of the question.
2. **Establish the integrity control for the script host process.** PPL for Defender processes, ELAM, and whether the host is a protected process. A protected script host cannot have its memory altered from user mode.
3. **Use the decoded-text event as the differential.** Script-block logging records the decoded content before the scan. If 4104 fires and no AMSI verdict follows, the scan path is broken; if both fire, the control works. That pair is the finding.
4. **Name the stop condition.** Stop at the first process that loads an unexpected `amsi.dll` or the first differential that shows decoded text without a verdict. Do not patch memory on a production host.
5. **State the proof.** Proof is the module path, the provider list, and the event differential. A tool that reports 'AMSI bypassed' without the differential is not evidence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `amsi.dll` loaded from a non-`System32` path | Proves DLL search-order redirection, which suppresses inspection for that process; Windows. |
| Empty AMSI provider list | Proves no script content inspection is registered at all; Windows with no AV product. |
| Event 4104 without a corresponding AMSI or Defender verdict | Proves the decode happened and the scan did not, the actual differential; Windows. |
| `AmsiScanBuffer` return value patched in memory | Proves in-memory tampering with the scan function, which requires unprotected process memory; Windows. |
| Protected process level on the script host | Proves user-mode tampering is not possible for that process; Windows with PPL configured. |

## Worked Contrast

**Weak configuration — script hosts can load amsi.dll from the working directory and no provider checks are enforced:**

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
# empty provider list, and a script host launched from a user-writable directory
# resolves amsi.dll from that directory before System32
(Get-Process powershell).Modules | Where-Object ModuleName -eq 'amsi.dll'
```

**Hardened configuration — providers registered and DLL search order constrained:**

```powershell
# deploy an AV product that registers an AMSI provider, and remove the
# current working directory from the DLL search path for script hosts
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
    -Name SafeDllSearchMode -Value 1
# verification: the provider list is populated and the loaded amsi.dll path is System32
```

**Why this matters:** the scan is only as good as the DLL and provider in use, so the controls are provider registration and search-order, and the verification is the loaded module path plus a verdict event.

## When It Is NOT This Issue

- **A missing AMSI verdict because the content was not script.** AMSI inspects script and macro content; a native binary produces no verdict by design.
- **A provider that returns clean for benign content.** That is the scan working correctly, not a bypass.
- **`amsi.dll` present but unused by a process.** Many processes load it without scanning anything; the finding requires the script path to be active.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `edr-evasion-and-amsi-bypass-amsi-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `edr-evasion-and-amsi-bypass-amsi-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: edr-evasion-and-amsi-bypass-amsi-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: T1562]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) - Blue Detection/Defense Counterpart
- [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](../edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `edr-evasion-and-amsi-bypass-amsi-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693, T1562`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/sigmahq (5), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
