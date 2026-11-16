---
name: windows-privilege-escalation-uac-bypass
description: Windows UAC bypass. Covers UAC bypass through auto-elevating binaries, registry hijacks, COM interface abuse and environment variable expansion. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["uac bypass", "bypass uac", "auto elevate", "uacme"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [windows-privilege-escalation, windows-privilege-escalation-token-and-privilege-abuse, windows-privilege-escalation-service-and-path-flaws, windows-privilege-escalation-credential-and-config-exposure]
parent: windows-privilege-escalation
---

# Windows Privilege Escalation UAC Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md)

## Mechanism and Preconditions

User Account Control is a consent boundary, not a security boundary: an administrator's token exists unfiltered and UAC only decides whether a process receives it without a prompt. Auto-elevating binaries and COM objects registered with auto-approval therefore cross that boundary silently. The finding requires an administrator account in the first place, which is why a UAC bypass on a standard user account is a category error, and the evidence is a new process with a high integrity token and no consent prompt.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the current user is not a local administrator **THEN** UAC bypass does not apply; the token has no elevated linked token to obtain
3. **IF** `ConsentPromptBehaviorAdmin` is 0 or 2 **THEN** auto-elevation is possible without a prompt; check the policy value rather than assuming the default
4. **IF** an auto-elevating binary is present and loads from a user-writable location **THEN** that is the classic bypass precondition; check the binary's manifest and load path
5. **IF** the elevation must persist **THEN** that is a different question; see [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-privilege-escalation-uac-bypass` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Kernel or driver primitives are the route | [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | Bypasses UAC entirely by running in kernel mode |
| A service DACL is the route | [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) | Reaches SYSTEM rather than high integrity |
| A token privilege is the route | [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) | Impersonation rather than elevation |
| Persistence after elevation | [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) | Durable mechanisms |
| Need the class-level branch table first | [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the account is an administrator and the token is filtered.** `whoami /groups` shows the `Mandatory Label\Medium Mandatory Level` and the Administrators group marked as deny-only. Without an elevated linked token there is nothing to obtain.
2. **Read the UAC policy values that decide the boundary.** `ConsentPromptBehaviorAdmin`, `EnableLUA`, and `FilterAdministratorToken` in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`. A value of 1 for `FilterAdministratorToken` also filters the built-in Administrator, which changes the answer.
3. **Baseline the integrity level before and after.** Capture `whoami /groups` integrity before the attempt and again after. The differential is a change from Medium to High with no consent prompt, which is the only unambiguous evidence of a bypass.
4. **Name the stop condition.** Stop at the first High-integrity process. Repeated attempts create multiple artefacts and can trigger EDR heuristics without adding evidence.
5. **State the proof.** Proof is a process whose integrity reads High and whose parent is the auto-elevating binary or COM surrogate, plus the policy value that permitted it. The bypass technique name is not evidence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ConsentPromptBehaviorAdmin` value 0 | Proves elevation happens without a prompt for administrators, the policy precondition; Windows with UAC configured by GPO. |
| Auto-elevating binary manifest `autoElevate` true | Proves the binary requests elevation without a prompt, which is the mechanism's prerequisite; Windows. |
| `FilterAdministratorToken` value 0 | Proves the built-in Administrator is unfiltered, which yields a directly elevated token; Windows. |
| COM object with `RunAs` `Interactive User` | Proves a COM hijack surface where the object is instantiated by an elevated process; Windows. |
| High-integrity process with a non-elevated parent | Proves the bypass succeeded, since the parent could not have created a high-integrity child directly; Windows. |

## Worked Contrast

**Weak configuration — administrators elevated without consent and a writable auto-elevate binary path:**

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name ConsentPromptBehaviorAdmin,EnableLUA,FilterAdministratorToken
# ConsentPromptBehaviorAdmin=0 elevates silently, and an auto-elevate binary
# resolves a DLL from a directory the user can write
```

**Hardened configuration — consent required and auto-elevation paths locked down:**

```powershell
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name ConsentPromptBehaviorAdmin -Value 2
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name EnableLUA -Value 1
# plus: remove write ACEs on directories in the binary's DLL search path
# verification: an elevation attempt now produces a consent prompt
```

**Why this matters:** UAC is a consent policy, so the control is the policy value plus the writable search path, and the verification is the prompt appearing rather than the technique failing.

## When It Is NOT This Issue

- **A standard user account.** Without an elevated linked token, no UAC bypass exists; the boundary is the account's group membership, not UAC.
- **A prompt the user approved.** A consented elevation is not a bypass; the differential requires no prompt and a high-integrity child.
- **A patched auto-elevating binary.** Microsoft has removed auto-elevation from several binaries over time; check the manifest on the installed build before reporting the precondition.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-privilege-escalation-uac-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-privilege-escalation-uac-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-privilege-escalation-uac-bypass
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
- [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-privilege-escalation-uac-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 23 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/sigmahq (16), CYBER_CPT/github_security_md (2), hackerone_disclosed_reports (1), cyber-security/vulnerability-intelligence__mitre-attack-techniques.json (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
