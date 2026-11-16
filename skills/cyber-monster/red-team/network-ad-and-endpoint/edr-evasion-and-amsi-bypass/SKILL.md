---
name: edr-evasion-and-amsi-bypass
description: "Evades endpoint detection and response and AMSI: understanding sensor telemetry, AMSI bypass mechanics, script and memory evasion, ETW patching, and testing against real defences. Use when endpoint security blocks a payload."
family: network-ad-and-endpoint
tier: core
triggers: ["edr evasion", "amsi bypass", "av bypass", "etw patch", "endpoint evasion", "defender evasion"]
cwe: [CWE-693]
owasp: []
attack: [T1562]
capec: [CAPEC-578]
related: [edr-evasion-and-amsi-bypass-amsi-bypass, edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion, edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls, network-recon-and-port-scanning]
---

# EDR Evasion and AMSI Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md)

## Mechanism and Preconditions

EDR evasion targets the observation layer rather than the operating system: if the sensor does not see the behaviour, the behaviour is not detected regardless of whether it is malicious. The relevant surfaces are the user-mode API hooks a product installs, the ETW providers it subscribes to, the AMSI interface that inspects script content, and the kernel callbacks it registers. Each has a corresponding integrity control, so the assessment is a question of which observation surface is unprotected rather than which technique works.

- **CWE-693 (Protection Mechanism Failure):** The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is script content inspection **THEN** use [`edr-evasion-and-amsi-bypass-amsi-bypass`](../edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md)
2. **IF** the target is ETW or event telemetry **THEN** use [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md)
3. **IF** the target is the sensor's own process **THEN** use [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) for the user-mode API question
4. **IF** the target is analysis-environment detection **THEN** use [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](../edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `edr-evasion-and-amsi-bypass` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Script content inspection is the surface | [`edr-evasion-and-amsi-bypass-amsi-bypass`](../edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md) | AMSI provider and interface |
| Event telemetry is the surface | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | ETW sessions and providers |
| User-mode hooks are the surface | [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) | API hook integrity |
| The environment reveals itself | [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](../edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection/SKILL.md) | Analysis-environment artefacts |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish what observation surfaces are actually present.** Registered AV and EDR products, AMSI providers, Sysmon configuration, ETW autologger sessions and kernel callbacks. Without this inventory the question 'is evasion possible' has no answer, because there may be nothing to evade.
2. **Read the integrity controls for each surface.** Tamper protection, PPL for the sensor process, ELAM, HVCI, and whether the sensor's own DLLs are protected. These decide whether the observation layer can be modified from user mode at all.
3. **Baseline the telemetry for a benign action.** Execute a known-benign action and record which events appear. The differential is the same action with the same technique applied and no event — that absence is the finding, and it is more reliable than a tool's success message.
4. **Name the stop condition and the safety rule.** Stop at the first surface shown to be unprotected. Do not disable a security product on a production host, and do not leave a driver or a patched in-memory region behind.
5. **State the proof.** Proof is the surface inventory plus a telemetry differential: the event that should have appeared and did not. A technique that 'worked' without a missing-event differential has not proven anything about detection.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| AMSI provider list under `HKLM\SOFTWARE\Microsoft\AMSI\Providers` | Proves script content is inspected by the named provider, and an empty list proves it is not; Windows. |
| Sysmon configuration version and rule coverage | Proves which behaviours are recorded, and a thin configuration proves the gap; Windows with Sysmon. |
| EDR process protection level | Proves whether the sensor runs as a protected process, which decides whether user-mode tampering is possible; Windows. |
| ETW autologger session list | Proves which providers are being collected, and their absence is the telemetry gap; Windows. |
| Tamper protection state | Proves whether a local administrator can change AV exclusions or disable real-time protection; Windows with Defender. |

## Worked Contrast

**Weak configuration — sensor unprotected, tamper protection off, Sysmon configuration minimal:**

```powershell
Get-MpComputerStatus | Select-Object IsTamperProtected,RealTimeProtectionEnabled
# IsTamperProtected False: a local administrator can set exclusions and disable
# real-time protection, and the Sysmon config records only process creation
```

**Hardened configuration — tamper protection on, sensor protected, Sysmon configuration covering the behaviours that matter:**

```powershell
Set-MpPreference -DisableTamperProtection $false   # where policy allows
# EDR: enable the vendor's tamper protection and early-launch driver
# Sysmon: deploy a maintained configuration covering events 1,3,6,7,8,10,11,13,22
# verification: IsTamperProtected reads True and a benign hook-removal attempt produces an alert
```

**Why this matters:** evasion works by changing the observation layer, so the controls are the protection of that layer and the coverage of its configuration, verified by a tamper attempt failing and by telemetry appearing.

## When It Is NOT This Issue

- **A missing event because the behaviour did not occur.** Absence of telemetry is only meaningful against a baseline where the same behaviour produced an event.
- **A product's own self-protection blocking a legitimate admin action.** That is the control working; distinguish it from an evasion success.
- **Sysmon not installed on a server.** Servers often rely on the EDR agent instead; check the full telemetry inventory before reporting a gap.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `edr-evasion-and-amsi-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `edr-evasion-and-amsi-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: edr-evasion-and-amsi-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: T1562]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) - Blue Detection/Defense Counterpart
- [`edr-evasion-and-amsi-bypass-amsi-bypass`](../edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](../edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `edr-evasion-and-amsi-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693, T1562`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 4 |
| Top sources | cyber-security/CyberSec-Dataset (8), CYBER_CPT/github_security_md (3), CYBER_CPT/blackhills (2), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
