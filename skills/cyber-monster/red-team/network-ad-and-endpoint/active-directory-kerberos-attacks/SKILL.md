---
name: active-directory-kerberos-attacks
description: "Exploits Kerberos in Active Directory: Kerberoasting, AS-REP roasting, delegation abuse, ticket forgery with golden and silver tickets, and S4U abuse. Use when a domain account exists and Kerberos pre-authentication is in play."
family: network-ad-and-endpoint
tier: flagship
triggers: ["kerberos attack", "kerberoast", "asrep roast", "golden ticket", "silver ticket", "delegation abuse"]
cwe: [CWE-269]
owasp: []
attack: [T1558]
capec: [CAPEC-509]
related: [active-directory-kerberos-attacks-kerberoasting, active-directory-kerberos-attacks-asrep-roasting, active-directory-kerberos-attacks-golden-and-silver-tickets, network-recon-and-port-scanning]
---

# Active Directory Kerberos Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **flagship** | Paired Counterpart: [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md)

## Mechanism and Preconditions

Kerberos in Active Directory issues tickets that are encrypted with keys derived from account passwords, and the KDC does not verify that a requester is entitled to a ticket for a given service principal. Three properties follow: any authenticated principal can request a service ticket for any SPN and take it away to crack offline; accounts without pre-authentication can be roasted from an unauthenticated position; and a ticket's PAC is trusted by services once it decrypts. Service-ticket encryption type is the pivot for most of the technique family, because RC4 tickets are orders of magnitude cheaper to attack than AES ones.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** SPN-bearing accounts are the target **THEN** use [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) for ticket request and encryption-type selection
2. **IF** accounts without pre-authentication exist **THEN** use [`active-directory-kerberos-attacks-asrep-roasting`](../active-directory-kerberos-attacks-asrep-roasting/SKILL.md); that path needs no credential
3. **IF** delegation is configured somewhere **THEN** use [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) for S4U semantics
4. **IF** a ticket must be forged or abused rather than cracked **THEN** use [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) and [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `active-directory-kerberos-attacks` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Service tickets for SPN-bearing accounts | [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) | Request path, encryption types, offline recovery |
| Accounts with pre-authentication disabled | [`active-directory-kerberos-attacks-asrep-roasting`](../active-directory-kerberos-attacks-asrep-roasting/SKILL.md) | No credential required |
| Constrained, unconstrained or RBCD delegation | [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) | S4U2Self and S4U2Proxy semantics |
| Forged or injected tickets | [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) | krbtgt and service-key trust |
| Tickets already held and need abusing | [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) | Pass-the-ticket and PAC behaviour |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the requesting conditions before requesting anything.** `userAccountControl` tells you which accounts lack pre-authentication, `servicePrincipalName` tells you which accounts are kerberoastable, and `msDS-SupportedEncryptionTypes` tells you which encryption types each account will accept. These three attributes decide every branch in this family.
2. **Fix the encryption-type baseline per account.** Record each target's supported types. RC4 (0x17) is what most tooling requests and what cracks cheaply; AES256 (0x12) is what a hardened account enforces. The differential is a returned ticket whose encryption type differs from that baseline, such as RC4 for an account that should be AES-only, and that difference is the finding.
3. **Choose the branch by preconditions, not by preference.** No credential and a pre-auth-disabled account: AS-REP. Any domain credential and an SPN: service ticket. Delegation configured: S4U. No delegation and no crackable account: the answer may be none of these, and saying so is a valid outcome.
4. **Set the stop condition at proof of requestability.** One returned ticket in an unexpected encryption type, or one AS-REP returned without pre-authentication, proves the exposure. Cracking the ticket is a separate authorised activity; the exposure finding does not depend on it.
5. **State the proof.** Proof is the KDC's response: a service ticket whose `TicketEncryptionType` is 0x17 for an account with `msDS-SupportedEncryptionTypes` restricted to AES, or an AS-REP issued without a pre-auth challenge. Cite the event id and the attribute values that produced it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `TicketEncryptionType` 0x17 in event 4769 | Proves a service ticket was issued with RC4, which is the cheap-to-attack case; domain controllers on Windows Server 2016 and later log this by default. |
| `userAccountControl` bit `DONT_REQ_PREAUTH` (0x400000) | Proves the account can be roasted without any credential; any AD. |
| `msDS-SupportedEncryptionTypes` per account | Proves whether RC4 is even permitted for that account, distinguishing an account-level weakness from a domain-level one; AD with modern functional level. |
| `krbtgt` key age and password last-set | Proves whether forged-TGT exposure can be closed by a double rotation, and how old the current key is; any AD. |
| `Get-ADUser -Filter {ServicePrincipalName -like '*'}` | Proves the kerberoastable account set, which is the scope of the whole family; any AD. |

## Worked Contrast

**Weak configuration — RC4 permitted domain-wide, so every service ticket is issued as 0x17:**

```powershell
Set-ADDomain -Identity corp.example -Replace @{'msDS-SupportedEncryptionTypes'=4}
# account-level value 4 = RC4 only; every TGS for these accounts comes back as 0x17
Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes |
    Where-Object { $_.msDS-SupportedEncryptionTypes -band 4 }
```

**Hardened configuration — AES-only encryption types with RC4 removed where compatibility allows:**

```powershell
Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes |
    Where-Object { $_.ServicePrincipalName -and ($_.msDS-SupportedEncryptionTypes -band 4) } |
    ForEach-Object { Set-ADUser $_.SamAccountName -Replace @{'msDS-SupportedEncryptionTypes'=24} }
# 24 = AES128 + AES256; verification: event 4769 now shows 0x12 for the same SPN
```

**Why this matters:** the crackability of a service ticket is decided by the encryption types the account advertises, so the attribute is the control and the ticket's `TicketEncryptionType` field is the verification.

## When It Is NOT This Issue

- **RC4 tickets for machine accounts.** Computers often negotiate RC4 for legacy compatibility; a machine account ticket in 0x17 is common and is a hygiene item, not a kerberoastable human account.
- **krbtgt tickets in 4769.** Tickets for `krbtgt` are TGT renewals, not roastable service tickets; filter them out before counting.
- **AES tickets assumed crackable.** An AES256 service ticket is not practically recoverable offline with current commodity hardware; describing it as equivalent to RC4 overstates the finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-kerberos-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-kerberos-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-kerberos-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1558]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-asrep-roasting`](../active-directory-kerberos-attacks-asrep-roasting/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-kerberos-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1558`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 34 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/oxdf (14), cyber-security/CyberSec-Dataset (8), CYBER_CPT/github_security_md (4), CYBER_CPT/hacktricks (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
