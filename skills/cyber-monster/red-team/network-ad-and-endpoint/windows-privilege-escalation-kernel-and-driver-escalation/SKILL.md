---
name: windows-privilege-escalation-kernel-and-driver-escalation
description: Windows kernel and driver local escalation. Covers local privilege escalation through kernel vulnerabilities and vulnerable drivers, including version targeting and reliability considerations. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["windows kernel exploit", "local privilege escalation windows", "driver lpe"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [windows-privilege-escalation, windows-privilege-escalation-token-and-privilege-abuse, windows-privilege-escalation-service-and-path-flaws, windows-privilege-escalation-credential-and-config-exposure]
parent: windows-privilege-escalation
---

# Windows Privilege Escalation Kernel and Driver Escalation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md)

## Mechanism and Preconditions

Kernel-mode code runs with no user-mode boundary above it, so a signed driver that exposes an arbitrary write, an arbitrary call, or a physical-memory mapping is an escalation primitive regardless of the driver's intent. The bring-your-own-vulnerable-driver technique depends on the driver still loading, which is decided by the Microsoft vulnerable driver blocklist, HVCI, and the driver's own signature. Because the blocklist is delivered with Windows updates and is also published separately, the version in force is the single most important fact in the assessment.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** a third-party driver is loaded **THEN** check its hash and name against the blocklist and LOLDrivers before anything else
3. **IF** HVCI or memory integrity is enabled **THEN** many vulnerable drivers that would otherwise load are blocked; the remaining set is smaller and documented
4. **IF** a driver can be loaded from a user-writable path **THEN** that is the strongest precondition, since the blocklist is bypassed only by a driver that is not listed
5. **IF** the question is whether the driver is malicious **THEN** that is malware triage, not privilege escalation; use the malware family skills
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-privilege-escalation-kernel-and-driver-escalation` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The token privilege is the route | [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) | SeLoadDriverPrivilege rather than a kernel primitive |
| The driver is the persistence mechanism | [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) | Service-based driver persistence |
| The driver is signed but abused by malware | [`byovd-and-driver-abuse`](../byovd-and-driver-abuse/SKILL.md) | Detection and triage of BYOVD campaigns |
| The target is EDR rather than the OS | [`edr-evasion-and-amsi-bypass`](../edr-evasion-and-amsi-bypass/SKILL.md) | Process termination and telemetry suppression |
| Need the class-level branch table first | [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate loaded and installed drivers with their signatures.** `driverquery /v` for loaded drivers, plus the service list filtered to `SERVICE_KERNEL_DRIVER`. Record the signer and the SHA256 of each binary, because the blocklist is keyed on hash and name rather than on version.
2. **Determine which protection layer is in force.** HVCI status, the blocklist version, and whether the driver was loaded before those were enabled. A driver already running is not removed by enabling HVCI, which is a common source of incorrect conclusions.
3. **Baseline against a host with the current blocklist.** A host with the blocklist applied and HVCI on is the reference. Drivers present on the assessed host but absent from the reference are the candidate set, provided their hashes are not on the blocklist.
4. **Name the stop condition.** Stop at the first driver whose hash is absent from the blocklist and which is loaded. Testing a kernel primitive itself is a state change with real crash risk and needs its own explicit authorisation.
5. **State the proof.** Proof is the driver's hash, its signer, its service state, the blocklist version in force, and the HVCI state. The vulnerable function inside the driver is only needed if the report must explain the primitive.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `driverquery /v` signer column | Proves which drivers are loaded and who signed them, the first filter for the candidate set; any Windows host. |
| SHA256 against the Microsoft blocklist | Proves whether the driver is blocked at this update level, which decides whether the primitive is reachable; any Windows host. |
| HVCI `Enabled` in `DeviceGuard` status | Proves memory integrity is enforced, which blocks many but not all vulnerable drivers; Windows 10 and 11, Server 2016 and later. |
| Driver loaded from `%TEMP%` or a user profile path | Proves the load path is user-writable, the strongest form of the finding; any Windows host. |
| LOLDrivers HVCI tag | Proves whether a catalogued driver still loads with memory integrity on, which narrows the set for a hardened estate; any Windows host. |

## Worked Contrast

**Weak configuration — a signed third-party driver from a user-writable path, absent from the blocklist:**

```powershell
Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' |
    Select-Object Name,PathName,StartMode
# C:\Users\Public\drv\vendor.sys loaded as a kernel service, hash not in the blocklist
# the driver exposes an IOCTL that maps physical memory to a caller-supplied buffer
```

**Hardened configuration — driver blocklist applied and HVCI enforced, so the load is refused:**

```powershell
# apply the Microsoft vulnerable driver blocklist via App Control for Business policy
# and enable memory integrity
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' `
    -Name Enabled -Value 1
# verification: the driver load returns a code-integrity error and the service fails to start
```

**Why this matters:** the primitive requires the driver to load, so the control is the blocklist plus HVCI and the verification is a failed load rather than a mitigated exploit.

## When It Is NOT This Issue

- **A driver already loaded before the blocklist was applied.** The blocklist prevents loading, not execution; a driver loaded earlier stays running until reboot, so check load time against the policy change.
- **An old blocklist version.** The blocklist is updated quarterly and also shipped with monthly updates; a host that has not applied either will allow drivers that current guidance blocks.
- **A driver signed by Microsoft but not vulnerable.** Many legitimate drivers appear in LOLDrivers as abused rather than vulnerable; check the classification before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-privilege-escalation-kernel-and-driver-escalation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-privilege-escalation-kernel-and-driver-escalation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-privilege-escalation-kernel-and-driver-escalation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1068]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) - Blue Detection/Defense Counterpart
- [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) - Network, Active Directory and Endpoint (flagship)
- [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-credential-and-config-exposure`](../windows-privilege-escalation-credential-and-config-exposure/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-uac-bypass`](../windows-privilege-escalation-uac-bypass/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-privilege-escalation-kernel-and-driver-escalation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/awesome_list (5), CYBER_CPT/L5/awesome_list (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
