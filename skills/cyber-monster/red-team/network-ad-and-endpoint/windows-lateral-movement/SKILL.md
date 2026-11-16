---
name: windows-lateral-movement
description: "Moves laterally between Windows hosts: SMB and admin shares, WinRM, WMI, scheduled tasks, service creation, PsExec-class techniques and RDP. Use once valid credentials or hashes are held."
family: network-ad-and-endpoint
tier: core
triggers: ["windows lateral movement", "lateral movement windows", "psexec", "winrm wmi", "pass the hash lateral"]
cwe: [CWE-269]
owasp: []
attack: [T1021]
capec: [CAPEC-122]
related: [windows-lateral-movement-smb-and-remote-execution, windows-lateral-movement-winrm-and-wmi, windows-lateral-movement-rdp-and-session-abuse, network-recon-and-port-scanning]
---

# Windows Lateral Movement - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Lateral movement in a Windows estate uses the administrative protocols that already exist: SMB for file and service creation, WinRM for shell remoting, WMI for process creation, RDP for interactive sessions, and scheduled tasks for deferred execution. Each leaves a different footprint — a service creation, a WinRM shell, a WMI provider host spawning a child, an RDP session logon — so technique selection is really a trade between the credential material held and the telemetry that will be produced.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the credential is a hash rather than a password **THEN** use [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md); NTLM authentication does not need the plaintext
2. **IF** SMB is open and admin shares are available **THEN** use [`windows-lateral-movement-smb-and-remote-execution`](../windows-lateral-movement-smb-and-remote-execution/SKILL.md)
3. **IF** WinRM or WMI is reachable **THEN** use [`windows-lateral-movement-winrm-and-wmi`](../windows-lateral-movement-winrm-and-wmi/SKILL.md)
4. **IF** interactive access is needed **THEN** use [`windows-lateral-movement-rdp-and-session-abuse`](../windows-lateral-movement-rdp-and-session-abuse/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `windows-lateral-movement` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Only a hash or ticket is held | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | NTLM and Kerberos without plaintext |
| SMB shares and service creation | [`windows-lateral-movement-smb-and-remote-execution`](../windows-lateral-movement-smb-and-remote-execution/SKILL.md) | Admin shares, service creation, PsExec-class |
| WinRM and WMI | [`windows-lateral-movement-winrm-and-wmi`](../windows-lateral-movement-winrm-and-wmi/SKILL.md) | Shell remoting and process creation |
| Interactive desktop access | [`windows-lateral-movement-rdp-and-session-abuse`](../windows-lateral-movement-rdp-and-session-abuse/SKILL.md) | Session logon and shadowing |
| The path must cross a network boundary | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Routing to an unreachable target |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm what the credential actually permits.** A local administrator hash on one host does not grant access to another unless the local account is reused. Enumerate local group membership on the target before choosing a protocol, because the technique is worthless without the right.
2. **Choose the protocol by the telemetry it produces.** Service creation writes event 7045 and 4697; WinRM writes 4103, 4104 and a `wsmprovhost` process; WMI writes 4688 with `WmiPrvSE` as parent; RDP writes 4624 logon type 10 and a session event. Naming the expected telemetry in the plan is what makes the test defensible.
3. **Baseline a legitimate administrative session.** Capture the target's normal admin activity for the same protocol from the sanctioned management host. The differential is the same event class arriving from an unauthorised source or with an unusual parent.
4. **Set the stop condition at authentication success.** A successful logon with the tool's output proves the path. Executing commands beyond a benign identity check is a state change on a production host and is not required for the finding.
5. **State the proof.** Proof is the target's own 4624 with `Logon Type`, `Authentication Package` and `Source Network Address`, correlated with the protocol-specific event. The source address is what distinguishes lateral movement from a legitimate admin session.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| 4624 logon type 3 with NTLM | Proves network logon with NTLM, the signature of hash-based movement; any Windows target. |
| Service Control Manager 7045 | Proves a service was created remotely, the PsExec-class footprint; any Windows target. |
| `wsmprovhost.exe` as a parent | Proves WinRM execution, since that process hosts the remote shell; Windows with WinRM enabled. |
| `WmiPrvSE.exe` spawning a child | Proves WMI process creation, the wmiexec footprint; any Windows target. |
| 4624 logon type 10 with a session event | Proves interactive RDP access, distinct from network logon; any Windows target with RDP. |

## Worked Contrast

**Weak configuration — local administrator accounts reused across the estate with no LAPS:**

```powershell
Get-LocalGroupMember -Group Administrators | Select-Object Name,PrincipalSource
# the same local Administrator password on every host, so one hash reaches all of them
# and no tier separation prevents a workstation hash from reaching a server
```

**Hardened configuration — LAPS-managed unique local passwords and tiered administration:**

```powershell
# deploy Windows LAPS with a unique password per host
Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=corp,DC=example'
# and restrict which accounts may log on to which tier via group policy
# verification: two hosts no longer share a local administrator hash
```

**Why this matters:** lateral movement depends on a credential that works elsewhere, so unique local passwords remove the reuse and tiering removes the cross-tier reach; the verification is that the same hash fails on a second host.

## When It Is NOT This Issue

- **A management platform using the same protocols.** SCCM, Ansible and patching tools create services and run WMI queries from sanctioned hosts; check the source address against the management inventory.
- **A local administrator account that is not reused.** A unique local password on one host grants nothing elsewhere; confirm reuse before reporting a lateral path.
- **RDP from a jump host.** Administrative RDP from a designated jump server is expected; the finding is a session from a workstation subnet.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-lateral-movement` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-lateral-movement` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-lateral-movement
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`windows-lateral-movement-smb-and-remote-execution`](../windows-lateral-movement-smb-and-remote-execution/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-lateral-movement-winrm-and-wmi`](../windows-lateral-movement-winrm-and-wmi/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-lateral-movement-rdp-and-session-abuse`](../windows-lateral-movement-rdp-and-session-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-lateral-movement` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1021`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/oxdf (11), CYBER_CPT/hacktricks (4), CYBER_CPT/github_security_md (2), CYBER_CPT/skullsecurity (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
