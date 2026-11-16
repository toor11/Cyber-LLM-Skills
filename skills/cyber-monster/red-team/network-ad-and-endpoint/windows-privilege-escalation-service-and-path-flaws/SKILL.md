---
name: windows-privilege-escalation-service-and-path-flaws
description: Windows service and path misconfiguration. Covers unquoted service paths, weak service ACLs, writable binaries and DLL search order hijacking. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["unquoted service path", "service acl", "dll hijack", "writable service binary"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [windows-privilege-escalation, windows-privilege-escalation-token-and-privilege-abuse, windows-privilege-escalation-credential-and-config-exposure, windows-privilege-escalation-uac-bypass]
parent: windows-privilege-escalation
---

# Windows Privilege Escalation Service and Path Flaws - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md)

## Mechanism and Preconditions

A Windows service is a privileged process whose configuration is an object with a DACL, and whose binary path is a string parsed by the Service Control Manager. Three flaws follow: the service DACL may let a non-administrator change the binary path or account; the path may be unquoted and contain spaces so that an intermediate directory is tried as an executable; and the binary may sit in a directory writable by a broader group than the service's own account. All three are object-state findings, not exploits, which is why they can be reported and remediated without running anything.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the service DACL grants `SERVICE_CHANGE_CONFIG` to a broad group **THEN** the binary path or account can be changed, which is a full boundary crossing
3. **IF** the path contains a space and is unquoted **THEN** check each intermediate directory for a write ACE; without one there is no finding
4. **IF** the binary is in a writable directory **THEN** that is the strongest form, because it needs no reconfiguration at all
5. **IF** the service runs as a domain account **THEN** the escalation target changes from SYSTEM to that account; record the account and its group membership
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-privilege-escalation-service-and-path-flaws` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The token is the boundary | [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) | Privileges held by the service account |
| The service is created by an installer | [`windows-service-and-scheduled-task-abuse`](../windows-service-and-scheduled-task-abuse/SKILL.md) | Service creation as an execution primitive |
| The scheduled task is the object | [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) | Task XML and its ACL |
| The binary loads a DLL from a writable path | [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | DLL search order in privileged processes |
| Need the class-level branch table first | [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the service's DACL and its binary path together.** `sc sdshow` gives the object DACL and `sc qc` the path and account. A writable DACL and a path in a privileged directory is one finding; a writable DACL alone is weaker, because it still requires a restart to take effect.
2. **Check the parsed path, not the quoted path.** For an unquoted path with spaces, Windows tries each prefix as an executable. Enumerate the intermediate directories and their ACLs; the finding exists only where an intermediate directory is writable by a group the current account belongs to.
3. **Record the restart behaviour.** A manual-start service can only be exploited with the ability to start it; an automatic service reloads at boot. The trigger condition belongs in the finding because it decides urgency.
4. **Baseline against a vendor-hardened install.** A correct install places the binary under `Program Files` with inherited restrictive ACLs, quotes the path, and restricts the service DACL to Administrators and SYSTEM. Deviation on any of the three is the finding.
5. **State the proof.** Proof is the ACL entry or the unquoted path plus the writable intermediate directory, read from the live object, together with the restart trigger. Replacing the binary is a state change and is not required to prove the finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `SERVICE_CHANGE_CONFIG` for `BUILTIN\Users` | Proves a non-administrator can repoint the binary, which is equivalent to running as the service account; any Windows host. |
| Unquoted path with a writable intermediate directory | Proves an executable can be planted where the SCM will look first; any Windows host with a legacy installer. |
| `SERVICE_START` for a broad group on a stopped service | Proves the trigger is available, which turns a latent flaw into a reachable one; any Windows host. |
| Writable directory containing the service binary | Proves replacement without any configuration change, the strongest form of the finding; any Windows host. |
| Service running as a domain account with local admin | Proves the escalation terminal state, which is what makes the flaw worth fixing; domain-joined hosts. |

## Worked Contrast

**Weak configuration — unquoted service path with a writable intermediate directory:**

```powershell
sc.exe qc LegacyAgent | Select-String 'BINARY_PATH_NAME'
# C:\Program Files\Legacy Agent\bin\agent.exe (unquoted)
icacls 'C:\Program Files\Legacy'
# BUILTIN\Users has (F) on the intermediate directory, so C:\Program Files\Legacy.exe is tried first
```

**Hardened configuration — quoted path with a locked-down intermediate directory:**

```powershell
sc.exe config LegacyAgent binPath= '"C:\Program Files\Legacy Agent\bin\agent.exe"'
icacls 'C:\Program Files\Legacy' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F'
# verification: qc shows the quoted path and icacls shows no write ACE for Users
```

**Why this matters:** the flaw is the combination of path parsing and directory permission, so both must change; quoting alone does not help if the directory stays writable.

## When It Is NOT This Issue

- **An unquoted path with no writable intermediate directory.** The parsing behaviour exists but nothing can be planted, so there is no boundary crossing.
- **A writable service directory that the service account also owns.** An application running from its own user-writable directory is a design choice; check whether the service runs as a privileged account before reporting.
- **A service DACL granting only read or interrogate.** `SERVICE_QUERY_STATUS` allows monitoring without changing anything; only change-config or start rights constitute the boundary.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-privilege-escalation-service-and-path-flaws` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-privilege-escalation-service-and-path-flaws` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-privilege-escalation-service-and-path-flaws
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
- [`windows-privilege-escalation-credential-and-config-exposure`](../windows-privilege-escalation-credential-and-config-exposure/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-uac-bypass`](../windows-privilege-escalation-uac-bypass/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-privilege-escalation-service-and-path-flaws` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/oxdf (3), CYBER_CPT/sigmahq (2), CYBER_CPT/blackhills (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
