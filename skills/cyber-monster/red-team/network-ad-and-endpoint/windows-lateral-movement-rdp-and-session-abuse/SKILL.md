---
name: windows-lateral-movement-rdp-and-session-abuse
description: RDP and session hijacking. Covers RDP access, session takeover, RDP shadowing and credential reuse, plus Restricted Admin and pass-the-hash over RDP where applicable. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["rdp lateral", "session hijack", "rdp shadow", "restricted admin"]
cwe: [CWE-269]
owasp: []
attack: [T1021]
capec: [CAPEC-122]
related: [windows-lateral-movement, windows-lateral-movement-smb-and-remote-execution, windows-lateral-movement-winrm-and-wmi, windows-lateral-movement-pass-the-hash-and-ticket]
parent: windows-lateral-movement
---

# Windows Lateral Movement Rdp and Session Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

RDP creates an interactive session with a full desktop token, which is qualitatively different from a network logon: the session loads the user's profile, maps their drives and printers, and can be shadowed by another administrator. The protocol negotiates its security layer before authentication, so NLA versus standard RDP and the certificate presented are visible pre-authentication. Session abuse covers hijacking an existing session, shadowing a live one, and using the drive-redirection channel to move files.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** NLA is not required **THEN** the logon screen is reachable pre-authentication, which widens the exposed surface; record the negotiation reply
3. **IF** an existing session must be taken over **THEN** session hijacking requires SYSTEM on the target and produces a distinctive `tscon` event
4. **IF** a session must be observed rather than taken **THEN** RDP shadowing requires the target's shadowing policy and produces its own event
5. **IF** the target is behind a gateway **THEN** the RD Gateway terminates TLS and the host's own RDP configuration is not externally visible
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-lateral-movement-rdp-and-session-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Network protocols rather than a desktop | [`windows-lateral-movement-winrm-and-wmi`](../windows-lateral-movement-winrm-and-wmi/SKILL.md) | Non-interactive execution |
| The session credential is a hash | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | RDP with restricted admin or pass-the-hash |
| The session must persist | [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) | Durable mechanisms |
| The exposure is the perimeter | [`initial-access-via-edge-devices`](../initial-access-via-edge-devices/SKILL.md) | Internet-facing remote access |
| Need the class-level branch table first | [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the negotiation before authenticating.** The X.224 reply names the selected security protocol: `PROTOCOL_HYBRID` for NLA with CredSSP, `PROTOCOL_RDP` for standard security. That single field decides whether the pre-auth surface exists, and it is readable without a credential.
2. **Confirm the authorising group and the session policy.** `Remote Desktop Users` membership plus the `fDenyTSConnections` value decide whether a session is possible at all. A reachable port with RDP denied is not a path.
3. **Baseline a legitimate administrative session.** Capture a session from the sanctioned jump host: 4624 logon type 10, the session-creation event, and the source address. The differential is the same logon from a workstation subnet.
4. **Set the stop condition at one authenticated session.** A single interactive logon proves the path. Interactive sessions are the most invasive form of access and should not be repeated for confirmation.
5. **State the proof.** Proof is the target's 4624 with logon type 10, `Source Network Address`, and the session id, plus the group membership and policy that permitted it. For shadowing, the shadow event on the target is the evidence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| 4624 logon type 10 | Proves an interactive remote session, distinct from a network logon; any Windows host with RDP. |
| X.224 reply without `PROTOCOL_HYBRID` | Proves NLA is not required, so the logon screen is reachable pre-authentication; any Windows host with RDP. |
| `fDenyTSConnections` value 0 | Proves RDP is enabled, the precondition for any session; any Windows host. |
| `tscon` invoked to move a session | Proves session hijacking, which requires SYSTEM on the target; Windows. |
| RDP shadow event with a controlling principal | Proves a shadowing session was established, which is observation rather than takeover; Windows with shadowing policy configured. |

## Worked Contrast

**Weak configuration — RDP exposed to the workstation subnet without NLA and with broad Remote Desktop Users membership:**

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name UserAuthentication,SecurityLayer
# UserAuthentication 0 (NLA not required) and SecurityLayer 0 (standard RDP security)
# the logon screen is reachable pre-authentication from any subnet that can route to 3389
```

**Hardened configuration — NLA required, TLS security layer, and host firewall scoped to the jump subnet:**

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name UserAuthentication -Value 1
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name SecurityLayer -Value 2
# and restrict 3389 to the jump host range at the firewall
# verification: the negotiation reply now requires PROTOCOL_HYBRID
```

**Why this matters:** the pre-authentication surface exists because NLA is optional, so the controls are `UserAuthentication` and the firewall scope, and the verification is the negotiation reply changing.

## When It Is NOT This Issue

- **RDP disabled but the port filtered.** A closed port and a disabled RDP service look similar from outside; check `fDenyTSConnections` before reporting exposure.
- **An RD Gateway in front of the host.** The gateway negotiates TLS on 443 and the host's own RDP settings are not externally reachable; the finding belongs to the gateway.
- **A session from the jump host.** Administrative RDP from a designated jump server is expected; the finding requires a source outside the sanctioned range.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-lateral-movement-rdp-and-session-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-lateral-movement-rdp-and-session-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-lateral-movement-rdp-and-session-abuse
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
- [`windows-lateral-movement-winrm-and-wmi`](../windows-lateral-movement-winrm-and-wmi/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-lateral-movement-rdp-and-session-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1021`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/atomic_red_team (2), CYBER_CPT/github_security_md (2), CYBER_CPT/expku (2), CYBER_CPT/secwiki (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
