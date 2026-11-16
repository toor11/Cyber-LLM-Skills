---
name: windows-privilege-escalation
description: "Escalates from a low-privileged Windows session to administrator or SYSTEM: service and permission misconfigurations, token abuse, unquoted paths, DLL hijacking, AlwaysInstallElevated, and credential exposure. Use on any Windows foothold."
family: network-ad-and-endpoint
tier: flagship
triggers: ["windows privesc", "windows privilege escalation", "winpeas", "seimpersonate", "unquoted service path"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [windows-privilege-escalation-token-and-privilege-abuse, windows-privilege-escalation-service-and-path-flaws, windows-privilege-escalation-credential-and-config-exposure, network-recon-and-port-scanning]
---

# Windows Privilege Escalation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **flagship** | Paired Counterpart: [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md)

## Mechanism and Preconditions

Windows privilege escalation is the search for a boundary that can be crossed from the current token's integrity level. The boundaries are distinct: a privilege the token holds but does not use, an object whose DACL permits modification, a service whose configuration or binary path is writable, an auto-elevating binary that loads code from a user-writable location, or a kernel primitive reachable from user mode. Each has its own precondition and its own false positive, so the methodology is boundary classification rather than a checklist of exploits.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a privilege such as SeImpersonate or SeDebug is enabled **THEN** use [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md)
2. **IF** a service binary path or DACL is writable **THEN** use [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md)
3. **IF** credentials or configuration files are readable **THEN** use [`windows-privilege-escalation-credential-and-config-exposure`](../windows-privilege-escalation-credential-and-config-exposure/SKILL.md)
4. **IF** an auto-elevating binary or COM interface is present **THEN** use [`windows-privilege-escalation-uac-bypass`](../windows-privilege-escalation-uac-bypass/SKILL.md)
5. **IF** a signed but vulnerable driver can be loaded **THEN** use [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-privilege-escalation` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Token privileges are the surface | [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) | SeImpersonate, SeAssignPrimaryToken, SeDebug, SeBackup |
| Service configuration and paths | [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) | Unquoted paths, weak DACLs, writable directories |
| Credential and configuration exposure | [`windows-privilege-escalation-credential-and-config-exposure`](../windows-privilege-escalation-credential-and-config-exposure/SKILL.md) | Unattend files, GPP, registry secrets |
| UAC as the boundary | [`windows-privilege-escalation-uac-bypass`](../windows-privilege-escalation-uac-bypass/SKILL.md) | Auto-elevation and COM hijack |
| Kernel and driver primitives | [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | BYOVD and vulnerable drivers |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Record the token baseline and the patch level.** `whoami /all`, the OS build and the hotfix list. A finding on a fully patched host that names a patched vulnerability is a false positive, and the build number is what prevents it.
2. **Enumerate boundaries rather than exploits.** Collect: enabled privileges, writable service objects and paths, writable directories in the system PATH, auto-elevating binaries, readable credential-bearing files, and loaded drivers with known vulnerabilities. This is a state inventory, not an exploitation run.
3. **Baseline against a hardened build of the same OS.** A reference host at the same build with the CIS or vendor baseline applied is the comparison. The finding is a deviation in object state, which is also what the remediation targets.
4. **Name the stop condition.** One boundary that can be crossed with a non-destructive proof is the finding. Running exploit frameworks that drop payloads or modify services turns an assessment into a state change, and the report does not need it.
5. **State the proof.** Proof is the object state that permits the crossing — the enabled privilege, the writable ACE, the unquoted path with a writable parent — plus a single non-destructive check that the state is as described. Proof of actual escalation is a separate, separately authorised step.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `whoami /priv` with `SeImpersonatePrivilege` enabled | Proves a token-impersonation boundary, typical of service accounts; any Windows host running IIS, MSSQL or scheduled tasks. |
| `sc qc <svc>` with an unquoted path containing a space | Proves a path-interpretation boundary where an intermediate directory may be writable; any Windows host. |
| Writable directory in a service's binary path | Proves the service can be made to load attacker code on restart; any Windows host. |
| `AlwaysInstallElevated` set in either HKLM or HKCU | Proves MSI packages install with elevated rights for any user; Windows with the policy enabled. |
| Loaded driver absent from the Microsoft vulnerable driver blocklist | Proves a BYOVD precondition rather than a vulnerability; any Windows host with third-party drivers. |

## Worked Contrast

**Weak configuration — service binary in a directory writable by authenticated users:**

```powershell
sc.exe qc SvcApp | Select-String 'BINARY_PATH_NAME'
# C:\ProgramData\Vendor\agent\svcapp.exe, and C:\ProgramData\Vendor is writable by Users
icacls C:\ProgramData\Vendor
# the service binary can be replaced and reloaded on the next restart
```

**Hardened configuration — binary moved under Program Files with an inherited restrictive ACL:**

```powershell
sc.exe config SvcApp binPath= 'C:\Program Files\Vendor\agent\svcapp.exe'
icacls 'C:\Program Files\Vendor' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F'
# verification: icacls shows no write ACE for Users and the service starts from the new path
```

**Why this matters:** the boundary is the writable parent directory of the loaded binary, so the control is the file ACL and the verification is reading it back rather than testing a replacement.

## When It Is NOT This Issue

- **A writable directory that is not in any service path.** Many application directories are user-writable by design; only directories on a privileged binary's load path constitute a boundary.
- **An unquoted path with no writable intermediate directory.** The classic unquoted-service-path finding requires a writable directory; without one it is a style issue.
- **A vulnerability patched at the current build.** Naming a CVE whose fix is included in the installed build is a false positive; always state the build and the fix version.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-privilege-escalation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-privilege-escalation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-privilege-escalation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1068]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) - Blue Detection/Defense Counterpart
- [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-credential-and-config-exposure`](../windows-privilege-escalation-credential-and-config-exposure/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-privilege-escalation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 9 |
| Top sources | CYBER_CPT/L5/ctf_search (6), CYBER_CPT/sigmahq (5), OffsecCyber (2), CYBER_CPT/cisa_kev (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 6 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
