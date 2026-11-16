---
name: active-directory-kerberos-attacks-kerberoasting
description: Kerberoasting. Covers requesting service tickets for SPN-bearing accounts and cracking them offline, including targeted SPN selection, RC4 downgrade and AES ticket handling. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["kerberoast", "spn crack", "kerberoasting attack"]
cwe: [CWE-269]
owasp: []
attack: [T1558]
capec: [CAPEC-509]
related: [active-directory-kerberos-attacks, active-directory-kerberos-attacks-asrep-roasting, active-directory-kerberos-attacks-golden-and-silver-tickets, active-directory-kerberos-attacks-delegation]
parent: active-directory-kerberos-attacks
---

# Active Directory Kerberos Attacks Kerberoasting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md)

## Mechanism and Preconditions

Kerberoasting requests a service ticket for an account that has a service principal name and takes the encrypted portion away for offline recovery. The KDC returns the ticket encrypted with a key derived from the service account's password, and it does so for any authenticated principal, because entitlement to the service is not checked at issuance. What decides cost is the encryption type: RC4-HMAC tickets are attackable at commodity GPU rates, while AES tickets are not practically recoverable, so the finding is usually the account's `msDS-SupportedEncryptionTypes` value rather than the request itself.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the account is restricted to AES encryption types **THEN** record it as a low-severity exposure and say so; calling an AES ticket crackable overstates the finding
3. **IF** the account is a machine account **THEN** computer accounts are commonly RC4 and are not usually crackable to a useful secret; check whether it is a user account first
4. **IF** the account has no SPN but you can write one **THEN** that is targeted kerberoasting and belongs to [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md)
5. **IF** the goal is a ticket for a specific privileged account **THEN** confirm it has an SPN and RC4 permitted; otherwise the path is shadow credentials or delegation, not roasting
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-kerberos-attacks-kerberoasting` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Writing an SPN first | [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) | Requires write on `servicePrincipalName` |
| No credential at all | [`active-directory-kerberos-attacks-asrep-roasting`](../active-directory-kerberos-attacks-asrep-roasting/SKILL.md) | Pre-auth-disabled accounts only |
| The account has an SPN and a privileged role | [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) | Using a ticket rather than cracking one |
| Offline recovery needs a strategy | [`password-cracking-and-wordlists`](../password-cracking-and-wordlists/SKILL.md) | Rule, mask and hardware tradeoffs |
| Need the class-level branch table first | [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the account class and its encryption types.** Read `objectClass`, `servicePrincipalName`, `msDS-SupportedEncryptionTypes` and `userAccountControl`. A user account with an SPN and only RC4 permitted is the exploitable case; a computer account or an AES-only account is a different, weaker finding.
2. **Take the encryption-type baseline from the directory, not from the ticket.** The KDC will issue whatever the account and domain permit. Record the account attribute first, then request the ticket and compare the returned `TicketEncryptionType`. A mismatch means domain policy is overriding the account, which is worth reporting separately.
3. **Request exactly one ticket for exactly one account.** One request per account is enough to prove issuance. Requesting every SPN in the domain generates hundreds of 4769 events and creates a detection signature out of proportion to the finding.
4. **Name the stop condition.** Stop after the ticket confirms the encryption type, or immediately if the account turns out to be AES-only. Cracking is a separate, separately authorised step and is not required to report the exposure.
5. **State the proof.** Proof is a 4769 event with `ServiceName` equal to the target account and `TicketEncryptionType` 0x17, together with the account's `msDS-SupportedEncryptionTypes` value showing RC4 permitted. A graph screenshot of an SPN account is a lead, not proof.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `impacket-GetUserSPNs -request` | Proves a service ticket is issued for the named account and shows its encryption type; user accounts with SPNs on any domain. |
| `Rubeus kerberoast /enctype:aes256` | Proves the KDC will issue AES on request, which is the comparison case showing what a hardened account looks like. |
| `msDS-SupportedEncryptionTypes` = 4 | Proves the account permits RC4 only, the account-level condition that makes a ticket cheap to attack; AD. |
| `TicketOptions` 0x40810000 with 0x17 | Proves a tool-shaped request rather than a normal service access, useful for both reporting and detection; domain controllers logging 4769. |
| SPN on a privileged account | Proves the blast radius: the recovered secret belongs to an account whose group membership reaches Tier-0; any AD. |

## Worked Contrast

**Weak configuration — service account with a user SPN and RC4 permitted:**

```powershell
Set-ADUser svc_sql -ServicePrincipalNames @{Add='MSSQLSvc/sql01.corp.example:1433'}
Set-ADUser svc_sql -Replace @{'msDS-SupportedEncryptionTypes'=4}
# any domain user can now request an RC4 service ticket for svc_sql and take it away
```

**Hardened configuration — gMSA with AES-only encryption and no interactive logon:**

```powershell
New-ADServiceAccount -Name svc_sql_gmsa -DNSHostName sql01.corp.example `
    -PrincipalsAllowedToRetrieveManagedPassword 'SQL01$'
Set-ADServiceAccount svc_sql_gmsa -Replace @{'msDS-SupportedEncryptionTypes'=24}
# verification: 4769 for the new SPN returns TicketEncryptionType 0x12, and the old account is disabled
```

**Why this matters:** the exposure is a user account whose secret is derivable from a crackable ticket, so moving to a managed account with AES-only types removes both the crackable ciphertext and the human-chosen password.

## When It Is NOT This Issue

- **AES-only account roasted anyway.** A ticket issued in AES256 is not practically recoverable; report the SPN exposure as a mapping issue, not a credential compromise path.
- **Computer account with an SPN.** Machine account passwords are long and random, so a roasted machine ticket is not a realistic recovery path; check the account class before assigning severity.
- **SPN on a disabled account.** A disabled account's ticket is not usable and its password may still be set to an old value; check `userAccountControl` before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-kerberos-attacks-kerberoasting` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-kerberos-attacks-kerberoasting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-kerberos-attacks-kerberoasting
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1558]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) - Network, Active Directory and Endpoint (flagship)
- [`active-directory-kerberos-attacks-asrep-roasting`](../active-directory-kerberos-attacks-asrep-roasting/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-kerberos-attacks-kerberoasting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1558`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (13), CYBER_CPT/github_security_md (7), bug-bounty-pentest-en (1), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
