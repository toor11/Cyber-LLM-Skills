---
name: byovd-and-driver-abuse
description: "Exploits vulnerable signed drivers to disable protections and escalate to kernel: BYOVD identification, vulnerable driver blocklist gaps, and practical abuse of known drivers. Use when userland protections block a goal and driver loading is possible."
family: network-ad-and-endpoint
tier: core
triggers: ["byovd", "vulnerable driver", "driver exploitation", "disable edr driver", "signed driver abuse"]
cwe: [CWE-781]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# BYOVD and Driver Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Bring-your-own-vulnerable-driver is a supply problem rather than an exploitation problem: a validly signed driver with a dangerous interface already exists, and an attacker only has to get it loaded. Since 2025 the interesting cases are drivers that are absent from both the Microsoft blocklist and the community catalogues, and re-signed variants that keep a valid signature while changing the hash. The detection opportunity is therefore the load event and the driver's provenance, not the payload that follows.

- **CWE-781 (Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code):** The product defines an IOCTL that uses METHOD_NEITHER for I/O, but it does not validate or incorrectly validates the addresses that are provided.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the driver is a security-product terminator **THEN** the mechanism is process termination from kernel mode; the finding is the driver's interface, not the payload
2. **IF** the driver is absent from the blocklist **THEN** record the gap and the blocklist version; that is the actionable report item
3. **IF** the driver is loaded from a user-writable path **THEN** any local user can supply it, which is the strongest form of the finding
4. **IF** the driver is in a campaign with many variants **THEN** hash-only rules will fail; look at publisher, signer chain and file name patterns
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `byovd-and-driver-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The driver provides a privilege-escalation primitive | [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | Escalation semantics |
| The driver blocks the blocklist enforcement | [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](../lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md) | Blocklist gaps |
| The driver suppresses telemetry | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | Event pipeline |
| The driver is part of a malware family | [`c2-implant-and-beaconing`](../c2-implant-and-beaconing/SKILL.md) | Family attribution from the resulting channel |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the driver by hash, signer and service name.** All three keys, because hash-based blocking fails against re-signed variants while signer and name rules survive.
2. **Establish the load path and the loading principal.** A kernel driver service created by a non-administrative principal is the precondition and the finding. Read the service's `ImagePath` and the creating account from 4697 or 7045.
3. **Read the blocklist and the HVCI state at load time.** The blocklist governs loading, so a host that loaded the driver before the update is still running it. Correlate the driver's load time with the policy change time.
4. **Baseline against a host at the current patch level.** A host with the current cumulative update and HVCI enabled is the reference. A driver that loads there is either not blocklisted or the enforcement is off.
5. **State the proof and stop.** Proof is the driver's hash and signer, the load event, the creating principal and the enforcement state. The vulnerable interface inside the driver is only needed if the report must explain the primitive.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Sysmon event 6 with `Signed: true` and a third-party signer | Proves a third-party driver loaded, which is the precondition for any BYOVD finding; Windows with Sysmon. |
| Service Control Manager 7045 with `Service Type: kernel driver` | Proves a driver service was installed, with the image path and account; Windows. |
| Multiple hashes with one valid signer | Proves re-signed variants and the insufficiency of hash-only blocking; Windows hosts in a campaign. |
| Driver path outside `System32\drivers` | Proves a user-writable load path, the strongest form of the finding; Windows. |
| Blocklist version older than the driver's catalogue entry | Proves a patch-management gap that the driver's availability depends on; Windows. |

## Worked Contrast

**Weak configuration — third-party drivers may load from user-writable paths with the blocklist unenforced:**

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' `
    -Name VulnerableDriverBlocklistEnable
# value 0: a signed driver placed in %TEMP% and registered as a kernel service
# loads without any blocklist consultation
```

**Hardened configuration — blocklist enforced, driver loading restricted to a signed allowlist:**

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' `
    -Name VulnerableDriverBlocklistEnable -Value 1
# plus an App Control for Business driver policy allowing only the approved publisher set
# verification: an unapproved driver load returns a code-integrity error
```

**Why this matters:** BYOVD requires the load, so the controls are blocklist enforcement plus a publisher allowlist, and the verification is a failed load rather than a detection.

## When It Is NOT This Issue

- **A legitimate third-party driver from a business application.** Antivirus, backup and VPN products ship signed drivers; provenance and publisher allowlisting separate them from abuse.
- **A driver blocked but already running.** Blocklist prevents loading; a driver loaded before enforcement continues until reboot, so check load time.
- **A driver in a catalogue classified as abused rather than vulnerable.** Not every catalogued driver has a usable primitive; check the classification before assigning severity.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `byovd-and-driver-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `byovd-and-driver-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: byovd-and-driver-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-781 | Mapping: T1068]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `byovd-and-driver-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-781, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/github_security_md (2), CYBER_CPT/sigmahq (1), CYBER_CPT/L5/awesome_list (1), CYBER_CPT/oxdf (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
