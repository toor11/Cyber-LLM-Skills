---
name: windows-lateral-movement-smb-and-remote-execution
description: SMB and remote execution lateral movement. Covers PsExec, SMBExec, atexec and service-based execution plus admin share abuse to run commands on remote hosts. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["psexec lateral", "smbexec", "atexec", "admin share execution"]
cwe: [CWE-269]
owasp: []
attack: [T1021]
capec: [CAPEC-122]
related: [windows-lateral-movement, windows-lateral-movement-winrm-and-wmi, windows-lateral-movement-rdp-and-session-abuse, windows-lateral-movement-pass-the-hash-and-ticket]
parent: windows-lateral-movement
---

# Windows Lateral Movement Smb and Remote Execution - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

SMB-based remote execution works because administrative shares and the Service Control Manager are reachable with administrative credentials. Three sub-primitives matter: writing a file to `ADMIN$` or `C$`, creating and starting a service whose binary points at that file, and remote scheduled task creation. Each writes distinct events — 5145 for share access, 7045 and 4697 for service installation, 4698 for task creation — and the file write is what makes the technique detectable before the service ever starts.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** `ADMIN$` and `C$` are reachable **THEN** file-based execution is available; the service creation step is what produces the strongest telemetry
3. **IF** SMB signing is required on the target **THEN** relay is closed but credentialed SMB still works; signing does not prevent authenticated access
4. **IF** the target has no writable admin share **THEN** remote scheduled tasks or WinRM may still work; check [`windows-lateral-movement-winrm-and-wmi`](../windows-lateral-movement-winrm-and-wmi/SKILL.md)
5. **IF** the credential is a hash **THEN** SMB accepts NTLM, so the path is unchanged; see [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-lateral-movement-smb-and-remote-execution` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| WinRM or WMI instead of SMB | [`windows-lateral-movement-winrm-and-wmi`](../windows-lateral-movement-winrm-and-wmi/SKILL.md) | Protocols that avoid admin shares |
| Only a hash is held | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | NTLM-based authentication |
| A service must be created for another purpose | [`windows-service-and-scheduled-task-abuse`](../windows-service-and-scheduled-task-abuse/SKILL.md) | Service and task semantics |
| The target is behind a network boundary | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Routing to the target |
| Need the class-level branch table first | [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm administrative rights on the target, not just authentication.** Local administrator group membership is the requirement, and it is readable with the credential. Authentication without that membership produces a share listing and nothing else.
2. **Read the target's SMB configuration first.** Signing requirement, SMB1 availability, and whether `ADMIN$` is enabled. These values decide which sub-primitive works and are also the hardening baseline.
3. **Choose the sub-primitive by the telemetry it leaves.** File write plus service creation leaves 5145 and 7045; remote scheduled task leaves 4698 and a task XML on disk; both are visible. Naming the expected events makes the test auditable and the report precise.
4. **Set the stop condition at one authenticated administrative action.** A directory listing of `ADMIN$` proves the rights without creating anything. That is sufficient for a scoping finding; creating a service is a state change that should be its own authorised step.
5. **State the proof.** Proof is the target's 4624 with logon type 3 plus 5145 for the admin share, and the local group membership that permitted it. For service creation, add 7045 with the binary path.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ADMIN$` write access | Proves file-based execution is possible with the credential and group membership; any Windows host with default admin shares. |
| Service Control Manager 7045 with a path under `ADMIN$` | Proves remote service-based execution, the PsExec footprint; any Windows host. |
| Windows Security 5145 with `Relative Target Name` under `ADMIN$` | Proves the file write that precedes service creation; any Windows host with share auditing. |
| Windows Security 4698 for a task created remotely | Proves scheduled-task-based execution, an alternative that leaves no service; any Windows host. |
| `RequireSecuritySignature` value | Proves whether signing is enforced, which matters for relay but not for credentialed SMB; any Windows host. |

## Worked Contrast

**Weak configuration — admin shares reachable from workstation subnets with no host firewall restriction:**

```powershell
Get-SmbShare -Name ADMIN$,C$ | Select-Object Name,Path
# no firewall rule limits 445 to the management subnet, so any host with a local
# admin credential can write to ADMIN$ and create a service
```

**Hardened configuration — SMB restricted to the management subnet and local admin rights reduced:**

```powershell
New-NetFirewallRule -DisplayName 'SMB-Mgmt-Only' -Direction Inbound -Protocol TCP `
    -LocalPort 445 -RemoteAddress 10.20.99.0/24 -Action Allow
New-NetFirewallRule -DisplayName 'SMB-Block-Others' -Direction Inbound -Protocol TCP `
    -LocalPort 445 -Action Block
# verification: an SMB connection from a workstation subnet now fails at the firewall
```

**Why this matters:** the path needs both the right and the reach, so the control is the network restriction on 445 plus the reduction of local admin rights, verified by a failed connection from the wrong subnet.

## When It Is NOT This Issue

- **Authentication without local administrator rights.** A valid credential that is not in the local Administrators group yields no admin share access; check group membership first.
- **Admin shares disabled by policy.** Some hardened builds remove `ADMIN$`; the technique is then unavailable regardless of rights.
- **SMB signing required.** Signing prevents relay, not credentialed access; do not report it as a barrier to this technique.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-lateral-movement-smb-and-remote-execution` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-lateral-movement-smb-and-remote-execution` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-lateral-movement-smb-and-remote-execution
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`windows-lateral-movement-winrm-and-wmi`](../windows-lateral-movement-winrm-and-wmi/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-lateral-movement-rdp-and-session-abuse`](../windows-lateral-movement-rdp-and-session-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-lateral-movement-smb-and-remote-execution` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1021`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/github_security_md (7), CYBER_CPT/hacktricks (6), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 8 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
