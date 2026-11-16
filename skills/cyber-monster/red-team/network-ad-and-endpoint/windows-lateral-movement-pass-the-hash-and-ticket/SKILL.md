---
name: windows-lateral-movement-pass-the-hash-and-ticket
description: Pass-the-hash and pass-the-ticket movement. Covers authenticating with hashes and Kerberos tickets instead of plaintext credentials across SMB, WMI and WinRM. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["pass the hash", "pass the ticket", "overpass the hash", "pth lateral"]
cwe: [CWE-269]
owasp: []
attack: [T1021]
capec: [CAPEC-122]
related: [windows-lateral-movement, windows-lateral-movement-smb-and-remote-execution, windows-lateral-movement-winrm-and-wmi, windows-lateral-movement-rdp-and-session-abuse]
parent: windows-lateral-movement
---

# Windows Lateral Movement Pass the Hash and Ticket - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

NTLM and Kerberos both authenticate without sending a password: NTLM proves knowledge of the hash, and Kerberos proves possession of a ticket. A recovered hash or ticket is therefore a reusable credential until the underlying secret changes. The methodology centres on applicability — a local account hash works only where that account exists with the same password, and a ticket works only until it expires and only for the services it names — so the first question is always which target the material actually reaches.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the material is a local account hash **THEN** applicability depends on password reuse; test one second host before proposing a path
3. **IF** the material is a domain account hash **THEN** applicability is the account's group membership and logon rights, not reuse
4. **IF** the material is a ticket **THEN** check its expiry and its service name; an expired or wrong-service ticket proves nothing
5. **IF** the material is an AES key rather than an NT hash **THEN** overpass-the-hash with AES produces Kerberos tickets and avoids NTLM entirely
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-lateral-movement-pass-the-hash-and-ticket` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| SMB and service-based execution | [`windows-lateral-movement-smb-and-remote-execution`](../windows-lateral-movement-smb-and-remote-execution/SKILL.md) | Where the hash is used |
| WinRM and WMI | [`windows-lateral-movement-winrm-and-wmi`](../windows-lateral-movement-winrm-and-wmi/SKILL.md) | Protocol alternatives that may accept the hash |
| The ticket came from memory | [`credential-dumping-lsass-and-memory`](../credential-dumping-lsass-and-memory/SKILL.md) | Where tickets are recoverable |
| The hash needs recovering | [`password-cracking-and-wordlists`](../password-cracking-and-wordlists/SKILL.md) | Offline recovery to plaintext |
| Need the class-level branch table first | [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Classify the material before using it.** NT hash, AES key, TGT, or service ticket. Each has a different applicability rule and a different detection signature, and mistaking one for another produces a failed path and a misleading report.
2. **Test applicability on a second host, not the source.** A hash that works on the host it was extracted from proves nothing about reach. The differential is a successful authentication on a second host where the account was never observed.
3. **Choose the protocol by what the target exposes and logs.** NTLM over SMB produces 4624 type 3 with `NTLM`; Kerberos produces `Kerberos` and a 4769 at the DC. The choice changes which log holds the evidence, so it belongs in the plan.
4. **Set the stop condition at one successful authentication.** One 4624 on a second host with the account's identity is the finding. Spreading the credential across the estate creates a large, hard-to-clean footprint.
5. **State the proof.** Proof is the target's 4624 naming the account, `Authentication Package`, `Logon Type` and `Source Network Address`, plus the reuse or group membership that made it possible. The tool's success line is not proof.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| 4624 logon type 3 with `NTLM` for a local account | Proves hash reuse reached a second host, which only happens with a shared local password; any Windows host. |
| 4624 with `Kerberos` and a 4769 at the DC | Proves ticket-based access, which leaves a request trail that NTLM does not; domain-joined hosts. |
| `klist` showing a service ticket for the target | Proves the ticket's service name matches the protocol in use; Windows client. |
| Local account `PasswordLastSet` differing between hosts | Proves unique local passwords and therefore no reuse path; any Windows host with LAPS. |
| `RestrictSendingNTLMTraffic` value | Proves the host will not send NTLM outbound, which bounds hash-based movement from it; Windows with the policy applied. |

## Worked Contrast

**Weak configuration — administrator hash reused across servers, with NTLM outbound unrestricted:**

```powershell
# same local Administrator password on every server, and NTLM outbound permitted
Get-ItemProperty 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name RestrictSendingNTLMTraffic
# one recovered hash authenticates to every server in the tier
```

**Hardened configuration — unique local passwords and NTLM restricted to an allowlist:**

```powershell
# Windows LAPS provides a unique local administrator password per host
# restrict NTLM outbound to the servers that still require it
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
    -Name RestrictSendingNTLMTraffic -Value 2
# verification: the hash no longer authenticates to a second host and NTLM audit shows no outbound use
```

**Why this matters:** hash reuse is a property of password equality and NTLM availability, so the controls are LAPS and the NTLM restriction, and the verification is a failed authentication on the second host.

## When It Is NOT This Issue

- **A hash that works only on its source host.** Local account reuse is not universal; test a second host before claiming a path.
- **A ticket for a service that does not exist on the target.** A service ticket names one SPN; using it against a different service fails regardless of privilege.
- **NTLM blocked outbound but Kerberos still permitted.** A failed hash authentication may reflect NTLM policy rather than credential invalidity; check both paths before concluding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-lateral-movement-pass-the-hash-and-ticket` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-lateral-movement-pass-the-hash-and-ticket` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-lateral-movement-pass-the-hash-and-ticket
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
- [`windows-lateral-movement-rdp-and-session-abuse`](../windows-lateral-movement-rdp-and-session-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-lateral-movement-pass-the-hash-and-ticket` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1021`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/atomic_red_team (4), CYBER_CPT/sigmahq (2), CYBER_CPT/hacktricks (2), CYBER_CPT/github_security_md (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
