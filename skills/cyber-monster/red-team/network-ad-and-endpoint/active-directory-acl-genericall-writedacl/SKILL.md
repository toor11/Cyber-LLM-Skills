---
name: active-directory-acl-genericall-writedacl
description: GenericAll and WriteDACL abuse. Covers abusing full control and DACL write rights to reset passwords, add members or grant further rights on users, groups and computers. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["genericall", "writedacl", "full control acl", "dacl abuse"]
cwe: [CWE-269]
owasp: []
attack: [T1098]
capec: [CAPEC-122]
related: [active-directory-acl-and-delegation-abuse, active-directory-acl-targeted-kerberoast-shadow-credentials, active-directory-acl-and-delegation-abuse-group-and-ou-abuse, network-recon-and-port-scanning]
parent: active-directory-acl-and-delegation-abuse
---

# Active Directory Acl and Delegation Abuse Genericall and Writedacl - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

`GenericAll` grants every right on an object at once, which makes it the simplest edge to reason about and the most damaging to leave in place. `WriteDACL` is subtler: it grants no data access by itself, but it lets the trustee add an ACE that grants anything, so its effective blast radius equals `GenericAll` with one extra step. Both are visible only in the object's security descriptor, which is why an inventory based on group membership systematically misses them.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the right is over a user object **THEN** a password reset plus attribute writes is sufficient, so the shortest path is usually a reset rather than a full impersonation chain
3. **IF** the right is over a computer object **THEN** the useful attribute is often `msDS-AllowedToActOnBehalfOfOtherIdentity`, so read the target's RBCD state next
4. **IF** the right is inherited from an OU **THEN** the finding is the OU-level ACE, and the remediation is at the OU, not on each child
5. **IF** the trustee is a legitimate administrative group **THEN** check whether the grant is the default set for that group before reporting; defaults are not findings
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-acl-genericall-writedacl` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The right is over a group or OU | [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](../active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md) | Nested membership and inheritance |
| The target attribute is a credential link | [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) | SPN and key-credential writes |
| The target is a computer and RBCD applies | [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) | S4U chain semantics |
| The right came from AdminSDHolder | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | Durable ACL mechanisms |
| Need the class-level branch table first | [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the descriptor and classify the ACE type.** Allow or deny, explicit or inherited, and which mask. A deny ACE earlier in the DACL can neutralise a later allow, so reading the effective rights in order matters more than listing ACEs.
2. **Determine what the right actually reaches.** `GenericAll` on a user reaches that user's credentials and attributes; on a computer it reaches the machine account and, through RBCD, potentially delegation. The blast radius is a property of the object class, not of the mask.
3. **Baseline the default grant for that trustee class.** Domain Admins hold broad rights by design. A non-tier-0 group with `GenericAll` over a Tier-0 object is the finding; the same group with read access is not.
4. **Stop at the first write-capable right over a Tier-0 object.** One proven `GenericAll` or `WriteDACL` over a privileged object is the finding. Enumerating every such right across the domain turns a report into an ACL dump.
5. **State the proof.** Proof is the ACE with trustee, mask and `ObjectType`, read from the live descriptor, plus the object's class and its Tier-0 status. A tool's edge label is derived data; the ACE is the record.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `GenericAll` (0xF01FF) on a user | Proves password reset, attribute write and DACL control over that account; any AD. |
| `WriteDACL` (0x40000) on an OU | Proves the trustee can grant itself any right over the container and its children; any AD. |
| `WriteOwner` (0x80000) on an object | Proves ownership takeover, which is followed by an implicit `WRITE_DAC` and then full control; any AD. |
| `ForceChangePassword` extended right GUID | Proves password reset alone, sufficient to take over the account without touching other attributes; any AD. |
| Deny ACE preceding an allow ACE | Proves the effective right is denied despite an allow further down the DACL, a common source of false findings; any AD. |

## Worked Contrast

**Weak configuration — WriteDACL granted to a non-tier-0 group over the Domain Admins group object:**

```powershell
$acl = Get-Acl 'AD:CN=Domain Admins,CN=Users,DC=corp,DC=example'
$acl.Access | Where-Object { $_.ActiveDirectoryRights -match 'WriteDacl' }
# the trustee can add itself to Domain Admins by editing the group's DACL, then its member attribute
```

**Hardened configuration — DACL write restricted to tier-0 administration groups:**

```powershell
$path = 'AD:CN=Domain Admins,CN=Users,DC=corp,DC=example'
$acl = Get-Acl $path
$acl.Access | Where-Object {
    $_.ActiveDirectoryRights -match 'WriteDacl' -and $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins'
} | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
Set-Acl -Path $path -AclObject $acl
# verification: the DACL read shows WriteDacl only for tier-0 groups
```

**Why this matters:** WriteDACL is equivalent to full control after one extra step, so the control is the trustee list on that specific right and the verification is re-reading the DACL rather than testing the write.

## When It Is NOT This Issue

- **An allow ACE overridden by a deny ACE.** Effective rights are evaluated in DACL order, so a deny earlier neutralises the allow; compute effective rights before reporting.
- **AdminSDHolder-propagated rights.** Protected accounts receive their ACL from `AdminSDHolder` on a schedule, so an ACE there is the real finding and the object-level copy is a symptom.
- **An ACE on a deleted-but-tombstoned object.** Tombstone reanimation rights on a deleted object container are a real but narrow edge; confirm the object still exists before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-acl-genericall-writedacl` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-acl-genericall-writedacl` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-acl-genericall-writedacl
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1098]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](../active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-acl-genericall-writedacl` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1098`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/oxdf (6) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
