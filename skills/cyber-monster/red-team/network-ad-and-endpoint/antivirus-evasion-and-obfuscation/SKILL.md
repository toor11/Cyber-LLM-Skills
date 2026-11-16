---
name: antivirus-evasion-and-obfuscation
description: "Evades signature and heuristic detection: loader design, encryption and encoding, packers, polymorphic stubs, string obfuscation and sandbox checks. Use when static detection blocks delivery."
family: network-ad-and-endpoint
tier: core
triggers: ["antivirus evasion", "av obfuscation", "packer", "loader", "payload encoding", "signature evasion"]
cwe: [CWE-693]
owasp: []
attack: [T1027]
capec: [CAPEC-578]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# Antivirus Evasion and Obfuscation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Antivirus evasion targets the signature and heuristic layer rather than the operating system: content is encoded, packed or split so static signatures miss it, and the original bytes are reassembled at run time. Because the reassembly step is the technique's weak point, the defender's leverage is the behaviour after decoding — a signed binary making a network request, a process writing an executable to a temp path, a script host decoding a base64 blob. The methodology therefore focuses on the decode-and-execute boundary rather than the encoded blob.

- **CWE-693 (Protection Mechanism Failure):** The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the content is a script rather than a binary **THEN** deobfuscation and script-block logging are the evidence; the encoded text itself is not
2. **IF** the content is a packed binary **THEN** the unpacking event and the resulting memory region are the evidence, not the file hash
3. **IF** delivery is expected to be retried after a block **THEN** that is a campaign signal; correlate blocks across hosts rather than analysing one sample
4. **IF** the question is whether the control works **THEN** run a benign encoded payload and check whether the control blocks at the decode boundary, not the encoder
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `antivirus-evasion-and-obfuscation` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| AMS.I bypass rather than AV evasion | [`edr-evasion-and-amsi-bypass-amsi-bypass`](../edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md) | Script scanning rather than file signatures |
| ETW suppression rather than content obfuscation | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | Telemetry loss rather than signature bypass |
| The evasion depends on a vulnerable driver | [`byovd-and-driver-abuse`](../byovd-and-driver-abuse/SKILL.md) | Kernel-level tampering |
| The sample needs triage | [`lolbins-and-signed-binary-abuse`](../lolbins-and-signed-binary-abuse/SKILL.md) | Signed-binary delivery |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish which control is being tested.** A file signature, a script-block scanner, an emulator, or a reputation service. Each has a different boundary, and a finding that does not name the control cannot be remediated or retested.
2. **Read the current policy and its telemetry.** AMSI providers registered, script-block logging enabled, Defender ASR rules in block or audit, and whether cloud-delivered protection is on. These values decide whether the boundary is even instrumented.
3. **Define the benign probe at the decode boundary.** A harmless encoded string that decodes to a marker command, run once, produces the differential: the scanner sees the decoded text and either blocks or logs it. That is a non-destructive test of the control.
4. **Name the stop condition and never use live malicious content.** The probe must be harmless and attributable. Stop at the first event that shows the control's decision, and never introduce real malicious content into a production estate to test a control.
5. **State the proof.** Proof is the control's own event — a Defender detection id, an AMSI block, an ASR rule id, or the absence of any event where one was expected. The probe's success or failure in an isolated lab is supporting material.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| AMSI provider registry list | Proves which script-scanning providers are registered, and therefore whether script content is inspected at all; Windows with an AV product. |
| Defender ASR rule state per rule GUID | Proves whether a specific behaviour is blocked, audited or off, which is the actionable control state; Windows. |
| PowerShell 4104 script-block logging | Proves decoded script text is recorded, the durable evidence after obfuscation; Windows with script-block logging enabled. |
| Sysmon event 1 with a base64-encoded `-EncodedCommand` | Proves the encoded-launch pattern, which is the delivery shape rather than the payload; Windows with Sysmon. |
| Defender detection history with a consistent threat name | Proves a signature identified the content family, which is the control working rather than failing; Windows with Defender. |

## Worked Contrast

**Weak configuration — script-block logging off, AMSI reachable from unmanaged code, ASR rules in audit only:**

```powershell
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
# no ASR ids configured, and ScriptBlockLogging is not enabled by policy,
# so an encoded script produces no decoded text anywhere
```

**Hardened configuration — script-block logging on, ASR rules blocking, AMSI providers registered:**

```powershell
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force
Add-MpPreference -AttackSurfaceReductionRules_Ids <rule-guid> `
    -AttackSurfaceReductionRules_Actions Enabled
# verification: an encoded launch produces a 4104 event with the decoded text
```

**Why this matters:** obfuscation defeats signatures but not decoding, so the controls are script-block logging and the ASR rule, and the verification is the decoded text appearing in an event.

## When It Is NOT This Issue

- **A base64 argument in a legitimate admin script.** Encoded commands are used by some management tooling; check the decoded content and the parent process before reporting.
- **A file detected as a generic heuristic.** A heuristic detection without a family name is a lower-confidence signal; confirm with behaviour before treating it as malware.
- **An AV exclusion for a backup or build directory.** Exclusions are a common and legitimate configuration; the finding is an exclusion for a user-writable path.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `antivirus-evasion-and-obfuscation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `antivirus-evasion-and-obfuscation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: antivirus-evasion-and-obfuscation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: T1027]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `antivirus-evasion-and-obfuscation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693, T1027`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/github_security_md (3), CYBER_CPT/gh_advisories (2), cyber-security/CyberSec-Dataset (1), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
