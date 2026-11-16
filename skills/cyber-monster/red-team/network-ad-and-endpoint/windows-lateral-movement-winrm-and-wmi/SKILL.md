---
name: windows-lateral-movement-winrm-and-wmi
description: WinRM and WMI lateral movement. Covers WinRM shelling and WMI process creation for stealthier remote execution with logging differences. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["winrm lateral", "wmi lateral", "evil-winrm", "wmiexec"]
cwe: [CWE-269]
owasp: []
attack: [T1021]
capec: [CAPEC-122]
related: [windows-lateral-movement, windows-lateral-movement-smb-and-remote-execution, windows-lateral-movement-rdp-and-session-abuse, windows-lateral-movement-pass-the-hash-and-ticket]
parent: windows-lateral-movement
---

# Windows Lateral Movement Winrm and Wmi - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

WinRM and WMI are management protocols that execute code by design, so administrative access to them is administrative execution with no exploit required. WinRM brings up a `wsmprovhost.exe` host process per shell and emits PowerShell engine logging; WMI creates a process through `WmiPrvSE.exe`, so the parent-child relationship is the tell. Both are frequently enabled for legitimate management, which is why the finding is the reachability and authorisation combination rather than the protocol presence.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** WinRM is reachable on 5985 or 5986 **THEN** shell remoting is available to any principal in the Remote Management Users group; check that group's membership
3. **IF** WMI is reachable on the RPC dynamic range **THEN** process creation is available to local administrators; check the target's group membership
4. **IF** the credential is a hash **THEN** WinRM accepts NTLM, so the path works without plaintext; see [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md)
5. **IF** the target is a domain controller **THEN** WinRM access there is Tier-0 equivalent; treat the finding accordingly
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-lateral-movement-winrm-and-wmi` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| SMB and service creation | [`windows-lateral-movement-smb-and-remote-execution`](../windows-lateral-movement-smb-and-remote-execution/SKILL.md) | File-based execution instead of a shell |
| Only a hash is held | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | NTLM authentication for either protocol |
| Interactive desktop access is needed | [`windows-lateral-movement-rdp-and-session-abuse`](../windows-lateral-movement-rdp-and-session-abuse/SKILL.md) | Session-level access |
| The management plane spans a boundary | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Routing to a management network |
| Need the class-level branch table first | [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the authorising group, not just the protocol.** WinRM requires membership of `Remote Management Users` or local Administrators; WMI process creation requires local Administrators. Read the group on the target with the credential, because protocol reachability alone proves nothing.
2. **Read the service configuration.** `winrm enumerate winrm/config/listener` gives the listener, port and authentication methods; the WMI service state and the RPC port range decide whether the WMI branch is available through a firewall.
3. **Choose the protocol by the telemetry it produces.** WinRM leaves PowerShell 4103 and 4104 plus `wsmprovhost.exe`; WMI leaves 4688 with `WmiPrvSE.exe` as parent and no shell process. Naming the expected event in the plan is what makes the test reviewable.
4. **Set the stop condition at one benign command.** A single `whoami` or hostname query through either protocol proves execution. Running tooling that writes files or changes configuration converts the test into a state change.
5. **State the proof.** Proof is the target's 4688 with the expected parent process, plus the 4624 that authorised it and the group membership that permitted it. A tool's output banner is not proof.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `wsmprovhost.exe` as the parent of a shell | Proves WinRM execution, since that process hosts the remote shell; Windows with WinRM enabled. |
| `WmiPrvSE.exe` spawning a child process | Proves WMI process creation through `Win32_Process::Create`; any Windows host. |
| Windows Security 4688 with `Creator Process Name` naming either host process | Proves the remote execution path directly from process creation auditing; any Windows host. |
| WinRM listener on 5985 plaintext | Proves credentials and commands traverse the network unencrypted unless message-level encryption is applied; Windows with WinRM configured. |
| `Remote Management Users` membership | Proves which principals can open a shell, independent of local administrator rights; Windows with WinRM. |

## Worked Contrast

**Weak configuration — WinRM listening on plaintext 5985 for all hosts and all authenticated users:**

```powershell
winrm enumerate winrm/config/listener
# Transport = HTTP, Port = 5985, and BUILTIN\Remote Management Users contains Domain Users
# so any domain user can open a shell on any host that allows WinRM
```

**Hardened configuration — HTTPS listener only, membership restricted, and host firewall scoped:**

```powershell
winrm create winrm/config/Listener?Address=*+Transport=HTTPS '@{Hostname="fs01";CertificateThumbprint="<thumb>"}'
winrm delete winrm/config/Listener?Address=*+Transport=HTTP
# restrict membership of Remote Management Users to a named administration group
# verification: netstat shows only 5986 listening and a shell attempt as a normal user fails
```

**Why this matters:** the exposure is the combination of a plaintext listener and broad group membership, so both must change; the verification is the listener list plus a failed shell for a non-administrative principal.

## When It Is NOT This Issue

- **WinRM enabled but restricted to a named group.** The protocol being available is normal management configuration; the finding is broad membership or a plaintext listener.
- **WMI used by monitoring software.** WMI queries from a sanctioned monitoring host are normal; distinguish queries from `Win32_Process::Create` calls.
- **A hash that authenticates but lacks group membership.** Authentication success is not execution success; check the authorising group.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-lateral-movement-winrm-and-wmi` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-lateral-movement-winrm-and-wmi` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-lateral-movement-winrm-and-wmi
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`windows-lateral-movement-smb-and-remote-execution`](../windows-lateral-movement-smb-and-remote-execution/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-lateral-movement-rdp-and-session-abuse`](../windows-lateral-movement-rdp-and-session-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-lateral-movement-winrm-and-wmi` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1021`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (9), CYBER_CPT/github_security_md (5), CYBER_CPT/hacktricks (1), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 10 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
