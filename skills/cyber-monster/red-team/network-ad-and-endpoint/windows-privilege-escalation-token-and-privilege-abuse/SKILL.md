---
name: windows-privilege-escalation-token-and-privilege-abuse
description: Windows token and privilege abuse. Covers SeImpersonate, SeAssignPrimaryToken, SeBackup and SeRestore abuse including potato-family techniques and backup operator privilege paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["seimpersonate", "potato attack", "sebackup", "token privilege escalation"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [windows-privilege-escalation, windows-privilege-escalation-service-and-path-flaws, windows-privilege-escalation-credential-and-config-exposure, windows-privilege-escalation-uac-bypass]
parent: windows-privilege-escalation
---

# Windows Privilege Escalation Token and Privilege Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md)

## Mechanism and Preconditions

A Windows token carries a set of privileges that are assigned at logon, and several of them cross a security boundary by design: `SeImpersonatePrivilege` permits adopting a token from another process, `SeAssignPrimaryTokenPrivilege` permits assigning one, `SeDebugPrivilege` permits opening any process, and `SeBackupPrivilege` permits reading any file regardless of its DACL. Service accounts habitually hold the first two, which is why web shells and database service accounts are a standard escalation position. The finding is the assignment, and the proof is that the privilege can be enabled and used.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** `SeImpersonatePrivilege` is enabled **THEN** the impersonation boundary applies; check whether a local service can be made to connect, since that is the token source
3. **IF** `SeDebugPrivilege` is enabled **THEN** process access is unrestricted, which reaches LSASS and any other process token
4. **IF** `SeBackupPrivilege` or `SeRestorePrivilege` is enabled **THEN** file DACLs are bypassed, which reaches registry hives and the SAM database
5. **IF** no sensitive privilege is enabled **THEN** this branch does not apply; look at service configuration or credential exposure instead
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-privilege-escalation-token-and-privilege-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The token comes from a local service | [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) | Producing a privileged token |
| The target process is LSASS | [`credential-dumping-lsass-and-memory`](../credential-dumping-lsass-and-memory/SKILL.md) | What the process access yields |
| The token is a domain identity | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | Reusing the identity elsewhere |
| The escalation must survive a reboot | [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) | Persistence mechanisms |
| Need the class-level branch table first | [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the privilege set and which entries are enabled.** `whoami /priv` distinguishes held from enabled privileges. A privilege that is held but disabled is still an escalation path where a caller can enable it, which is why both states matter.
2. **Identify the token source before attempting anything.** Impersonation requires a token to adopt, usually from a service that authenticates locally. Enumerate services running as SYSTEM or Network Service that accept a connection from the current account.
3. **Baseline the current integrity and the target's.** Record `whoami /groups` integrity for the current process and the target's token integrity. The differential is a change from Medium or High to System, which is the only unambiguous evidence.
4. **Set the stop condition at the first token acquisition.** One SYSTEM token proves the boundary. Repeated acquisition creates duplicate service artefacts and makes cleanup harder without adding evidence.
5. **State the proof.** Proof is a process whose token integrity reads `System` and whose `whoami /priv` shows the full privilege set, together with the service interaction that produced the token. The tool name is not evidence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `SeImpersonatePrivilege` enabled | Proves a token-adoption boundary, typical of IIS app pool identities and MSSQL service accounts; Windows. |
| `SeAssignPrimaryTokenPrivilege` enabled | Proves a process-creation boundary where an arbitrary token can be assigned to a new process; Windows. |
| `SeDebugPrivilege` enabled | Proves unrestricted process access, which reaches LSASS memory and other processes' tokens; Windows. |
| `SeBackupPrivilege` and `SeRestorePrivilege` together | Proves file DACL bypass in both directions, which reaches registry hives and the SAM; Windows. |
| `SeTakeOwnershipPrivilege` enabled | Proves object ownership takeover, followed by an implicit `WRITE_DAC`; Windows. |

## Worked Contrast

**Weak configuration — an IIS application pool identity holding SeImpersonatePrivilege:**

```powershell
# app pool runs as a virtual account with SeImpersonatePrivilege enabled
whoami /priv | Select-String 'SeImpersonate'
# the identity can adopt a token from any local service it can make authenticate,
# which reaches SYSTEM without any further misconfiguration
```

**Hardened configuration — app pool on a restricted identity with the privilege removed:**

```powershell
# move the app pool to a dedicated service account without the privilege
Set-ItemProperty 'IIS:\AppPools\CorpApp' -Name processModel.identityType -Value SpecificUser
# and remove the account from the local policy assignment 'Impersonate a client after authentication'
secedit /export /cfg secpol.inf
# verification: whoami /priv for the app pool identity no longer lists SeImpersonate
```

**Why this matters:** the boundary is the privilege assignment in local security policy, so the control is the assignment list and the verification is re-reading the effective privileges of the identity.

## When It Is NOT This Issue

- **A privilege that is disabled and cannot be enabled.** Some privileges are held but not enableable by the token's integrity; check whether the enable step actually succeeds before reporting.
- **A service account that legitimately requires SeImpersonate.** IIS and MSSQL service identities need it to function; the finding is that they also have a path to a SYSTEM token, not the privilege alone.
- **SeDebugPrivilege on a local administrator.** Administrators hold it by design; the finding requires a non-administrative account holding it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-privilege-escalation-token-and-privilege-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-privilege-escalation-token-and-privilege-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-privilege-escalation-token-and-privilege-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1068]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) - Blue Detection/Defense Counterpart
- [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) - Network, Active Directory and Endpoint (flagship)
- [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-credential-and-config-exposure`](../windows-privilege-escalation-credential-and-config-exposure/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-uac-bypass`](../windows-privilege-escalation-uac-bypass/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-privilege-escalation-token-and-privilege-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (10), CYBER_CPT/hacktricks (3), CYBER_CPT/github_security_md (2), CYBER_CPT/heresecurity (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 11 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
