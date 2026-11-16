---
name: windows-internals-and-api-abuse
description: "Uses Windows internals deliberately: token manipulation, handle duplication, privilege enabling, PPL and protected process targeting, and native API versus Win32 paths. Use when standard tooling is insufficient or detected."
family: network-ad-and-endpoint
tier: leaf
triggers: ["windows internals", "token manipulation", "handle duplication", "native api", "ntdll", "ppl"]
cwe: [CWE-269]
owasp: []
attack: [T1134]
capec: [CAPEC-233]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# Windows Internals and API Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Most Windows privilege boundaries are enforced by kernel objects rather than by a single check, so an assessment reads object state: what token a process holds, which privileges that token enables, what the object's DACL permits, and whether a protection such as PPL or Credential Guard sits in front of the target. API abuse is the act of using a documented call in an unintended sequence — opening a process with a broader mask than needed, duplicating a token, or creating an object with a permissive descriptor — so the evidence is always the object's state before and after, not the call itself.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a token must be examined **THEN** read `whoami /priv`, `/groups` and `/all` first; the enabling privileges and group integrity decide everything downstream
2. **IF** an object handle is the question **THEN** use `handle.exe` or the object's DACL rather than guessing from process names
3. **IF** a security product is blocking access **THEN** check whether the target is a PPL, whether HVCI is on, and whether Credential Guard is enabled before concluding the technique is patched
4. **IF** the question is escalation from a service account **THEN** go to [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `windows-internals-and-api-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The token has dangerous privileges | [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) | SeImpersonate, SeAssignPrimaryToken, SeDebug |
| The object is a service or its path | [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) | Service DACL and binary path |
| The object is a driver | [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | Kernel-mode primitives |
| The boundary is UAC rather than the kernel | [`windows-privilege-escalation-uac-bypass`](../windows-privilege-escalation-uac-bypass/SKILL.md) | Auto-elevation and consent |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the current token before anything else.** `whoami /all` gives privileges, groups, integrity level and logon type. Every Windows escalation path is relative to that baseline, and a finding that does not name the integrity level cannot be reproduced.
2. **Identify the boundary being tested.** A token boundary (privilege), a DACL boundary (object access), an integrity boundary (UIPI), or a protection boundary (PPL, HVCI, Credential Guard). Each has a different check and a different false positive, so naming it prevents the most common reporting error.
3. **Baseline the object's security descriptor.** Read the DACL or the privilege state before the probe, so a change is attributable. For a service, `sc sdshow`; for a process, its token; for a driver, its load state and signature.
4. **Stop at the first boundary that actually moves.** One successful integrity or privilege transition is the finding. Probing every API on the host produces crashes and EDR alerts without adding evidence.
5. **State the proof.** Proof is the object state after the technique: a token with a different integrity level, a process running as SYSTEM, or a write to a protected path. The API call is the mechanism, not the evidence; the state change is.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `whoami /priv` privilege list | Proves which privileges the token holds and, more importantly, which are enabled; any Windows host. |
| `whoami /groups` integrity level | Proves the integrity boundary in force, which decides whether UIPI blocks a write; Windows Vista and later. |
| `sc sdshow <service>` | Proves the service object's DACL, which is the surface for service reconfiguration; any Windows host. |
| Token `TokenElevationType` and linked token | Proves whether an elevated token exists and is merely filtered by UAC; Windows with UAC enabled. |
| Object `Mandatory Label` ACE | Proves the mandatory integrity policy on an object, which is what a low-integrity process cannot cross; Windows Vista and later. |

## Worked Contrast

**Weak configuration — a service account holding SeImpersonate with a permissive service DACL:**

```powershell
whoami /priv | Select-String 'SeImpersonatePrivilege'
# SeImpersonatePrivilege Enabled, and the service's DACL grants SERVICE_CHANGE_CONFIG
# to BUILTIN\Users, so the binary path can be repointed without admin rights
```

**Hardened configuration — privilege removed from the service account and the DACL tightened:**

```powershell
$sd = sc.exe sdshow SvcApp
# replace the ACE granting SERVICE_CHANGE_CONFIG to BUILTIN\Users, then:
sc.exe sdset SvcApp $tightenedSd
# and remove SeImpersonatePrivilege from the account's logon rights assignment
# verification: whoami /priv no longer lists SeImpersonate, and sc config fails for a standard user
```

**Why this matters:** both halves are object state, so the control is the privilege assignment plus the service DACL, and the verification is re-reading both rather than testing an exploit.

## When It Is NOT This Issue

- **A privilege that is present but disabled.** `SeDebugPrivilege` listed as Disabled cannot be used without an explicit enable step; report the assignability, not an immediate capability.
- **Administrator-created objects with broad DACLs.** Objects created by an installer during setup often have permissive DACLs by design; check whether the object is production or scaffolding before reporting.
- **Protection that the tooling cannot see.** A PPL-protected process denies handle requests regardless of privilege; an access-denied result may be the protection working, not the privilege missing.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-internals-and-api-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-internals-and-api-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-internals-and-api-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1134]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-internals-and-api-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1134`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 8 |
| Top sources | cyber-security/CyberSec-Dataset (7), CYBER_CPT/atomic_red_team (5), SecEval/attck (2), CYBER_CPT/github_security_md (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
