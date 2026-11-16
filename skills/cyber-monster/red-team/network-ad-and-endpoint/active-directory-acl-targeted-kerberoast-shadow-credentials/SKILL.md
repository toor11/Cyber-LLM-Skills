---
name: active-directory-acl-targeted-kerberoast-shadow-credentials
description: Shadow credentials and targeted abuse. Covers adding Key Credential Link shadow credentials to a computer or user to authenticate as it, plus targeted SPN and ACL chains. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["shadow credentials", "key credential link", "msds-keycredentiallink", "whisker"]
cwe: [CWE-269]
owasp: []
attack: [T1098]
capec: [CAPEC-122]
related: [active-directory-acl-and-delegation-abuse, active-directory-acl-genericall-writedacl, active-directory-acl-and-delegation-abuse-group-and-ou-abuse, network-recon-and-port-scanning]
parent: active-directory-acl-and-delegation-abuse
---

# Active Directory Acl and Delegation Abuse Targeted Kerberoast and Shadow Credentials - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Two attributes turn a write permission into an authentication primitive without changing the account's password. Writing `servicePrincipalName` on a user makes it kerberoastable, so a ticket encrypted with its key can be requested and attacked offline. Writing `msDS-KeyCredentialLink` on any account installs an attacker-supplied public key, after which PKINIT returns a TGT for that account. Both are legitimate features — service registration and Windows Hello for Business — which is why the grants persist, and both are invisible to password-based reviews.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the write is on `servicePrincipalName` **THEN** the account becomes roastable; check its encryption types and password strength before predicting impact
3. **IF** the write is on `msDS-KeyCredentialLink` **THEN** the account can be authenticated as without any password change, and the modification is reversible and quiet
4. **IF** the target is a computer account **THEN** key-credential abuse against computers is the classic shadow-credential path, and RBCD often follows
5. **IF** the write right is absent **THEN** this technique does not apply; look for delegation or a password-reset right instead
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-acl-targeted-kerberoast-shadow-credentials` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The right is full control rather than one attribute | [`active-directory-acl-genericall-writedacl`](../active-directory-acl-genericall-writedacl/SKILL.md) | GenericAll and WriteDACL |
| The goal is a ticket for an SPN account | [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) | Ticket request without writing an SPN |
| The target is a computer and RBCD follows | [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) | Delegation after key installation |
| The key must survive remediation | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | Durable key-credential abuse |
| Need the class-level branch table first | [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the write right on the specific attribute GUID.** `servicePrincipalName` is `f3a64788-5306-11d1-a9c5-0000f80367c1` and `msDS-KeyCredentialLink` is `5b47d60f-6090-40b2-9f37-2a4de88f3063`. A `GenericAll` includes them; a narrow `WriteProperty` ACE may name just one, and the specific GUID decides which technique applies.
2. **Read the target's current state before writing anything.** For an SPN target, record existing SPNs and encryption types. For a key-credential target, record existing `msDS-KeyCredentialLink` values, because Windows Hello for Business may already have installed keys and your addition would be one of several.
3. **Baseline the account's authentication pattern.** Note the hosts and logon types the account normally uses. The differential after the technique is a Kerberos authentication from a host and logon type the account has never used.
4. **Set the stop condition and the restoration step.** Stop at the first successful TGT or service ticket. Because both techniques modify the directory, record the original attribute value and restore it, since leaving an SPN or key behind changes production state permanently.
5. **State the proof.** SPN case: the written `servicePrincipalName` value plus a 4769 for that SPN. Key case: the added key credential thumbprint plus a 4768 issued via PKINIT for that account. A write permission alone is a precondition, not the finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `msDS-KeyCredentialLink` write ACE | Proves shadow-credential preconditions: the trustee can install a key and authenticate as the target; any AD with Windows Hello for Business or Key Trust. |
| `servicePrincipalName` write ACE | Proves targeted kerberoasting preconditions with no password change, which leaves no `pwdLastSet` evidence; any AD. |
| 4768 with `PreAuthType` 16 (PKINIT) | Proves a TGT was issued using a certificate rather than a password, the shadow-credential signature; domain controllers. |
| Key credential thumbprint in the attribute | Proves an attacker-supplied key is installed and can be matched against the certificate used; any AD. |
| `ms-DS-MachineAccountQuota` above zero | Proves any user can create a computer account, which supplies the target for several key-credential and RBCD paths; default domains. |

## Worked Contrast

**Weak configuration — a plain domain user can write msDS-KeyCredentialLink on a Tier-0 user:**

```powershell
$acl = Get-Acl 'AD:CN=adm_target,OU=Privileged,DC=corp,DC=example'
$acl.Access | Where-Object { $_.ObjectType -eq [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063' }
# the trustee can install a key and obtain a TGT as adm_target without a password change
```

**Hardened configuration — key-credential write restricted to tier-0 and the account's own management path:**

```powershell
$path = 'AD:CN=adm_target,OU=Privileged,DC=corp,DC=example'
$acl = Get-Acl $path
$acl.Access | Where-Object {
    $_.ObjectType -eq [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063' -and
    $_.IdentityReference -notmatch 'Domain Admins'
} | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
Set-Acl -Path $path -AclObject $acl
# verification: reading the attribute ACL shows only tier-0 trustees
```

**Why this matters:** the capability is a single attribute write, so the control is the ACE on that GUID; password rotation does not remediate it, which is why the descriptor is the only honest verification.

## When It Is NOT This Issue

- **Existing Hello for Business keys.** A populated `msDS-KeyCredentialLink` is normal in a Key Trust deployment; the finding is who can write it, not that it holds values.
- **An SPN that legitimately belongs to a service account.** Service accounts are supposed to have SPNs; the finding is a write right over that attribute on a privileged account, not the existence of the SPN.
- **A write right scoped by a deny ACE.** Effective rights matter, so a deny earlier in the DACL neutralises the grant; compute effective rights before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-acl-targeted-kerberoast-shadow-credentials` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-acl-targeted-kerberoast-shadow-credentials` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-acl-targeted-kerberoast-shadow-credentials
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1098]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`active-directory-acl-genericall-writedacl`](../active-directory-acl-genericall-writedacl/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](../active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-acl-targeted-kerberoast-shadow-credentials` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1098`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/github_security_md (3), CYBER_CPT/sigmahq (1), CYBER_CPT/hacktricks (1), CYBER_CPT/oxdf (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
