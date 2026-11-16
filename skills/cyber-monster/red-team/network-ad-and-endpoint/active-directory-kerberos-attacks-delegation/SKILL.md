---
name: active-directory-kerberos-attacks-delegation
description: Kerberos delegation abuse. Covers unconstrained, constrained and resource-based constrained delegation exploitation including S4U2Self and S4U2Proxy chains. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["kerberos delegation", "unconstrained delegation", "constrained delegation", "s4u", "rbcd kerberos"]
cwe: [CWE-269]
owasp: []
attack: [T1558]
capec: [CAPEC-509]
related: [active-directory-kerberos-attacks, active-directory-kerberos-attacks-kerberoasting, active-directory-kerberos-attacks-asrep-roasting, active-directory-kerberos-attacks-golden-and-silver-tickets]
parent: active-directory-kerberos-attacks
---

# Active Directory Kerberos Attacks Delegation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md)

## Mechanism and Preconditions

Delegation lets a service obtain tickets on behalf of a user, and each form has a different trust assumption. Unconstrained delegation caches the user's full TGT on the service host, so compromising that host yields every delegating user's ticket. Constrained delegation uses S4U2Proxy to limit which services can be reached, but S4U2Self lets a service assert any user's identity to itself, which is enough to pivot. Resource-based constrained delegation moves the control to the target object's `msDS-AllowedToActOnBehalfOfOtherIdentity`, so write access to that attribute is the precondition.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the account is a computer with `TRUSTED_FOR_DELEGATION` **THEN** unconstrained; the finding is which users' TGTs land on that host, so enumeration of delegating users matters more than the flag
3. **IF** `msDS-AllowedToDelegateTo` is populated **THEN** constrained; the finding is which of the listed SPNs are themselves privileged
4. **IF** `msDS-AllowedToActOnBehalfOfOtherIdentity` is populated **THEN** RBCD; the finding is who can write that attribute, not just who is listed in it
5. **IF** the account is marked sensitive and cannot be delegated **THEN** it is excluded from delegation, so a path requiring its TGT does not exist; check the flag before ranking
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-kerberos-attacks-delegation` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The target needs a ticket cache | [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) | Pass-the-ticket semantics |
| Tickets must be forged from keys | [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) | krbtgt and service key trust |
| Write access to the RBCD attribute is the edge | [`active-directory-acl-genericall-writedacl`](../active-directory-acl-genericall-writedacl/SKILL.md) | ACL rights that permit the write |
| The terminal asset is a domain controller | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | What durable access looks like after delegation abuse |
| Need the class-level branch table first | [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Classify the delegation form from the attributes.** `userAccountControl` bit 0x80000 for unconstrained, a non-empty `msDS-AllowedToDelegateTo` for constrained, and a non-empty `msDS-AllowedToActOnBehalfOfOtherIdentity` for RBCD. These are mutually informative but not exclusive; read all three.
2. **Identify who can trigger the delegation.** For unconstrained, the trigger is any user authenticating to the host, so enumerate which privileged principals have sessions there. For RBCD, the trigger is write access to the target's attribute, so read the target's DACL.
3. **Baseline against the default delegation posture.** A domain with `Account is sensitive and cannot be delegated` set on Tier-0 accounts and no unconstrained delegation outside a small set of legacy hosts is the reference. Deviation on either axis is the finding.
4. **Stop at the first proven control relationship.** One host with unconstrained delegation and a privileged session, or one target whose RBCD attribute is writable by a non-tier-0 principal, is sufficient. Enumerating every delegating user adds volume, not proof.
5. **State the proof.** Unconstrained: the host's `TRUSTED_FOR_DELEGATION` flag plus an observed privileged logon on that host. Constrained: the `msDS-AllowedToDelegateTo` list containing a Tier-0 SPN. RBCD: the target attribute plus the DACL entry naming a non-tier-0 trustee.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `TRUSTED_FOR_DELEGATION` (0x80000) in `userAccountControl` | Proves unconstrained delegation, where any delegating user's TGT is cached on that host; any AD. |
| `msDS-AllowedToDelegateTo` | Proves constrained delegation targets and whether any is a Tier-0 service; any AD. |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | Proves RBCD configuration, where the controlling factor is who may write it; AD 2012 functional level and later. |
| `NOT_DELEGATED` (0x100000) on a privileged account | Proves the account is excluded from delegation, which removes otherwise plausible paths; any AD. |
| `SeEnableDelegationPrivilege` holders | Proves who can grant delegation at all, which is a Tier-0-equivalent right; domain controllers. |

## Worked Contrast

**Weak configuration — unconstrained delegation on a host that privileged users administer:**

```powershell
Set-ADAccountControl -Identity WEB01$ -TrustedForDelegation $true
# every privileged user who authenticates to WEB01 leaves a usable TGT in its LSASS
Get-ADComputer WEB01 -Properties userAccountControl,msDS-AllowedToDelegateTo
```

**Hardened configuration — delegation removed and privileged accounts marked not delegatable:**

```powershell
Set-ADAccountControl -Identity WEB01$ -TrustedForDelegation $false
Get-ADUser -Filter {AdminCount -eq 1} | ForEach-Object {
    Set-ADAccountControl -Identity $_.SamAccountName -AccountNotDelegated $true
}
# verification: the computer's flag reads false and a privileged logon no longer caches a TGT there
```

**Why this matters:** the risk is the cached TGT, so the control is removing the delegation flag and excluding privileged accounts from delegation, verified by re-reading the account control bits.

## When It Is NOT This Issue

- **Delegation to a non-privileged SPN.** Constrained delegation to a single low-value web service is a designed configuration; check what the listed SPNs can reach before raising it.
- **RBCD on a host whose attribute only tier-0 can write.** If the DACL restricts the write to Domain Admins, the configuration is not an escalation edge.
- **A host with delegation but no privileged logons.** Unconstrained delegation on a host that only machine accounts authenticate to yields machine TGTs, which is a much weaker finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-kerberos-attacks-delegation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-kerberos-attacks-delegation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-kerberos-attacks-delegation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1558]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) - Network, Active Directory and Endpoint (flagship)
- [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-asrep-roasting`](../active-directory-kerberos-attacks-asrep-roasting/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-kerberos-attacks-delegation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1558`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/hacktricks (4), CYBER_CPT/oxdf (3), CYBER_CPT/blackhills (2), cyber-security/CyberSec-Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
