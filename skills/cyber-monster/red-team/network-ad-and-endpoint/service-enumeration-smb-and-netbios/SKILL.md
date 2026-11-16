---
name: service-enumeration-smb-and-netbios
description: SMB and NetBIOS enumeration. Covers share listing, null sessions, SMB version and signing detection, user enumeration and RID cycling. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["smb enum", "null session", "smb signing", "rid cycling", "share enumeration"]
cwe: [CWE-284]
owasp: []
attack: [T1046]
capec: [CAPEC-116]
related: [service-enumeration, service-enumeration-ldap-and-directory, service-enumeration-database-and-remote-access, service-enumeration-snmp-and-infrastructure]
parent: service-enumeration
---

# Service Enumeration Smb and Netbios - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

SMB enumeration reads the negotiation and session-establishment layer before any file access happens. The server's dialect list, signing requirement, and whether a null session is accepted are all visible in the first few packets, and those three facts decide whether relay, guest access, or anonymous share listing is even possible. NetBIOS name service adds the legacy discovery layer, where a name query returns the host's registered names and workgroup without credentials.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`service-enumeration`](../service-enumeration/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** signing state is the actual question **THEN** read the negotiate reply first; `smb2-security-mode` reports required versus enabled, and only required defeats relay
3. **IF** the host answers but no share lists **THEN** check whether the session is guest or null; a guest session often sees fewer shares than an authenticated one and proves less
4. **IF** NetBIOS name queries are the only answer on the segment **THEN** enumerate names with `nmblookup`, then map the suffix to the service role before scanning ports
5. **IF** the goal becomes relaying rather than reading **THEN** switch to [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) so signing and coercion preconditions are handled together
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `service-enumeration-smb-and-netbios` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Relay is the objective, not enumeration | [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) | Signing and channel binding decide feasibility |
| The host is a domain controller | [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) | Directory metadata is the richer surface |
| Shares are found and now need permission mapping | [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) | ACL and group context for share access |
| NetBIOS names imply a legacy protocol stack | [`network-protocol-attacks-name-resolution-poisoning`](../network-protocol-attacks-name-resolution-poisoning/SKILL.md) | NBT-NS answers are a poisoning surface |
| Need the class-level branch table first | [`service-enumeration`](../service-enumeration/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the negotiation reply before requesting anything.** Extract the dialect chosen, the signing-required flag, and the server's name. This one exchange answers whether SMB1 exists, whether signing is enforced, and what the host calls itself.
2. **Separate null, guest and authenticated sessions.** Run the same share query three ways: no credential, guest credential, and the authorised identity. Each result is a different exposure claim, and conflating them is the most common error in SMB reporting.
3. **Baseline against a hardened member server.** A Server 2025 member with signing required and guest disabled is the reference. Deviation on dialect range, signing or guest access is the finding; parity means the host is behaving as designed.
4. **Stop at the first proof of the claim.** One successful anonymous share listing proves anonymous read exposure. Enumerating further shares or recursively listing files adds no proof and increases the chance of touching sensitive data you did not need.
5. **State the proof precisely.** Anonymous access is proven by a share list or file listing returned without credentials. Relay feasibility is proven by a negotiation reply in which signing is not required, together with a coerced or captured authentication from that host.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `nmap -p445 --script smb2-security-mode,smb2-capabilities` | Proves signing requirement and SMB2/3 dialect support per host; Windows and Samba. |
| `netexec smb host --shares -u "" -p ""` | Proves whether a null session reaches the share enumeration RPC; Windows and Samba. |
| `smbclient -L //host -N` | Proves anonymous share listing and the share comment strings, which often name the business function; Samba client against any SMB server. |
| `nmblookup -A 10.20.30.20` | Proves registered NetBIOS names and their suffix codes, which identify role (domain controller, workstation, master browser); any NBNS responder. |
| `netexec smb 10.20.30.0/24 --gen-relay-list` | Proves which hosts in a range do not require signing, producing the relay candidate set; Windows estate. |

## Worked Contrast

**Weak configuration — SMB signing not required and guest access enabled:**

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $true -Force
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
# negotiation reply now shows signing not required, so any captured NTLM can be relayed here
```

**Hardened configuration — signing required, SMB1 removed, guest disabled:**

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -RestrictNamedPipeAccessToRemoteClients $true -Force
# negotiation reply now shows signing required; relay to this host fails at session setup
```

**Why this matters:** the control is enforced in the negotiate and session-setup exchange, so `smb2-security-mode` before and after the change is the verification, not a registry value read.

## When It Is NOT This Issue

- **Signing enabled but not required.** `EnableSecuritySignature` true with `RequireSecuritySignature` false still permits an unsigned session; reporting it as 'signing on' is wrong and hides the relay path.
- **Guest access on a hardened appliance.** Some NAS and print devices only expose guest shares by design; check whether the share contains anything beyond driver or spool data before raising it.
- **SMB1 present but unused.** A dialect in the negotiate list is not the same as an SMB1 session being established; confirm with a session that actually negotiates SMB1 before reporting legacy exposure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `service-enumeration-smb-and-netbios` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `service-enumeration-smb-and-netbios` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: service-enumeration-smb-and-netbios
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1046]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration-database-and-remote-access`](../service-enumeration-database-and-remote-access/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration-snmp-and-infrastructure`](../service-enumeration-snmp-and-infrastructure/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `service-enumeration-smb-and-netbios` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1046`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/oxdf (6), CYBER_CPT/L5/ctf_search (2), OffsecCyber (1), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
