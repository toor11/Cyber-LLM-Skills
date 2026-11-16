---
name: ntlm-relay-and-coercion-relay-targets
description: NTLM relay target selection. Covers relaying to SMB, LDAP, HTTP enrollment and MSSQL, including signing requirements, channel binding and EPA considerations. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["ntlm relay ldap", "relay to smb", "relay epa", "channel binding relay"]
cwe: [CWE-294]
owasp: []
attack: [T1557]
capec: [CAPEC-589]
related: [ntlm-relay-and-coercion, ntlm-relay-and-coercion-coercion-primitives, network-recon-and-port-scanning, service-enumeration]
parent: ntlm-relay-and-coercion
---

# NTLM Relay and Coercion Relay Targets - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

A relay target must accept an NTLM authentication whose integrity it cannot verify against the original channel. Four settings decide this: SMB signing required, LDAP signing required, LDAP channel binding enforced, and EPA on HTTP services. Any one of them, correctly applied, defeats the relay for that protocol. Target selection is therefore a configuration audit ranked by what a successful relay would grant — domain controller LDAP (object creation, RBCD), AD CS web enrollment (a certificate), or a file server (share access).

- **CWE-269 (Improper Privilege Management):** privilege, delegation or ACL handling lets a principal act outside its intended sphere.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** SMB signing is required on every host **THEN** SMB relay is closed; look at LDAP and HTTP targets instead
3. **IF** LDAP signing is required and channel binding enforced **THEN** LDAP relay is closed for LDAPS; check whether plain LDAP 389 is still permitted
4. **IF** an HTTP endpoint accepts NTLM without EPA **THEN** that is the most productive target class, including AD CS web enrollment
5. **IF** the relay succeeds but grants nothing useful **THEN** the privilege of the relayed account is the limit; a machine account relayed to LDAP can create objects but not read the domain
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `ntlm-relay-and-coercion-relay-targets` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| No authentication is being produced | [`ntlm-relay-and-coercion-coercion-primitives`](../ntlm-relay-and-coercion-coercion-primitives/SKILL.md) | Primitive availability per backing service |
| Certificate enrollment is the target | [`active-directory-certificate-services-esc5-through-esc8`](../active-directory-certificate-services-esc5-through-esc8/SKILL.md) | ESC8 endpoint conditions |
| The relayed identity is a machine account | [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) | What RBCD from a machine account reaches |
| The target must be reached across a boundary | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Routing the listener to the victim |
| Need the class-level branch table first | [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Build the target matrix before choosing anything.** For each candidate host: SMB signing state, LDAP signing state, channel-binding enforcement, and whether an HTTP endpoint accepts NTLM. This matrix is the deliverable; the relay attempt is a confirmation of one cell.
2. **Rank targets by the privilege a successful relay would convey.** A domain controller's LDAP with signing unenforced and an over-permissive machine-account quota allows object creation and RBCD. A file server allows share access at the relayed account's privilege. Rank by consequence, not by ease.
3. **Confirm the target's state with a read, not a relay.** `smb2-security-mode`, the LDAP `dSHeuristics`/`LdapEnforceChannelBinding` registry value, and the IIS EPA setting each give the answer without sending a relayed authentication. Do that first; it is faster and leaves no relay traffic.
4. **Name the stop condition.** Stop at the first target whose configuration permits relay and whose relayed identity would grant something material. Sending relays against every host in the matrix is unnecessary once one cell is proven.
5. **State the proof.** Proof is the configuration read plus, if the relay is authorised, the target's 4624 with the victim's machine account and the assessment host's source address. A configuration read alone supports a hardening finding; only the 4624 supports a demonstrated path.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `RequireSecuritySignature` per SMB server | Proves whether SMB relay is possible to that host; any Windows or Samba server. |
| `LdapEnforceChannelBinding` value | Proves whether LDAPS relay is defeated; domain controllers. Value 2 means always, 1 means when supported, 0 means never. |
| `dSHeuristics` LDAP signing requirement | Proves whether unsigned LDAP binds are refused; domain controllers. |
| EPA `tokenChecking` on an IIS site | Proves whether an HTTP endpoint validates channel binding, which is the AD CS relay control; IIS-hosted services. |
| `ms-DS-MachineAccountQuota` | Proves whether a relayed machine account can create further machine accounts, which extends a relay into a delegation chain; default domains. |

## Worked Contrast

**Weak configuration — domain controllers accept unsigned LDAP and unbound LDAPS:**

```powershell
reg query 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' /v LdapEnforceChannelBinding
# 0x0 = never enforced; unsigned LDAP binds and unbound LDAPS are both accepted
# a relayed machine account can create objects and set msDS-AllowedToActOnBehalfOfOtherIdentity
```

**Hardened configuration — channel binding required and LDAP signing enforced:**

```powershell
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' /v RequireSigning /t REG_DWORD /d 1 /f
Restart-Service NTDS -Force
# verification: an unsigned or unbound LDAP bind now fails with a channel-binding error
```

**Why this matters:** the relay succeeds only because the target cannot tie the authentication to the original channel, so channel binding and signing are the controls and a failed bind is the verification.

## When It Is NOT This Issue

- **LDAP 389 open but signing required.** Port 389 being reachable is not a relay path; the signing requirement is what decides it.
- **A target with signing required but NTLM permitted.** Signing defeats relay while still allowing NTLM logons for other purposes; do not report the NTLM setting as the finding.
- **Relay to a low-privilege machine account.** A relayed machine account on a hardened domain often grants nothing beyond what the account already had; check the resulting privilege before reporting a path.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ntlm-relay-and-coercion-relay-targets` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ntlm-relay-and-coercion-relay-targets` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ntlm-relay-and-coercion-relay-targets
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-294 | Mapping: T1557]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`ntlm-relay-and-coercion`](../ntlm-relay-and-coercion/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`ntlm-relay-and-coercion-coercion-primitives`](../ntlm-relay-and-coercion-coercion-primitives/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ntlm-relay-and-coercion-relay-targets` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-294, T1557`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 21 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (19), CYBER_CPT/hacktricks (1), CYBER_CPT/blackhills (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
