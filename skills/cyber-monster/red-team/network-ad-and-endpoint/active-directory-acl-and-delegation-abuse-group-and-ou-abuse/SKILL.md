---
name: active-directory-acl-and-delegation-abuse-group-and-ou-abuse
description: Group and OU permission abuse. Covers abusing group membership rights, OU delegated control, GPO link rights and AdminSDHolder-adjacent permissions. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["group abuse", "ou permissions", "gpo link abuse", "delegated control"]
cwe: [CWE-269]
owasp: []
attack: [T1098]
capec: [CAPEC-122]
related: [active-directory-acl-and-delegation-abuse, active-directory-acl-genericall-writedacl, active-directory-acl-targeted-kerberoast-shadow-credentials, network-recon-and-port-scanning]
parent: active-directory-acl-and-delegation-abuse
corpus_sparse: true
---

# Active Directory Acl and Delegation Abuse Group and Ou Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Group and OU rights compound: an `AddMember` right on a group grants the group's access, and a `WriteProperty` right on an OU covers every object inside it, including objects created later. Nested group membership then hides the effect, because the trustee of the ACE is a group whose members are themselves groups. The methodology is to resolve both directions — which groups the trustee belongs to, and which objects the container will ever hold.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the right is `AddMember` on a privileged group **THEN** resolve the group's effective access first; adding a member is only valuable if the group has access worth having
3. **IF** the right is on an OU **THEN** enumerate what the OU contains now and what default location new objects use, since future objects inherit the same exposure
4. **IF** the trustee is nested several levels deep **THEN** resolve the full transitive membership before ranking; a group with no direct members may still contain every user
5. **IF** the right is over a GPO rather than an OU **THEN** use [`active-directory-enumeration-gpo-and-administrative-discovery`](../active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-acl-and-delegation-abuse-group-and-ou-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The right is full control on one object | [`active-directory-acl-genericall-writedacl`](../active-directory-acl-genericall-writedacl/SKILL.md) | GenericAll and WriteDACL semantics |
| The target attribute is credential-bearing | [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) | SPN and key-credential writes |
| The path runs through policy | [`active-directory-enumeration-gpo-and-administrative-discovery`](../active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md) | GPO edit rights and linkage |
| The group grants host-level access | [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) | What the group membership enables on hosts |
| Need the class-level branch table first | [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Resolve transitive membership in both directions.** The trustee's own group closure, and the members of the target group. An `AddMember` right over a group with no members and no access is worthless; over `Domain Admins` it is a full domain compromise.
2. **Determine container inheritance explicitly.** An ACE with `ContainerInherit` applies to existing and future children. Check the OU's default-object location settings too, because a writable OU that receives new computer objects by default will accumulate exposure.
3. **Baseline the intended delegation.** Most organisations publish a delegation model: helpdesk resets in a user OU, server operators in a server OU. Compare the actual ACEs against that model; deviation is the finding, and it is also the remediation target.
4. **Stop at the first ACE whose container reaches Tier-0.** One writable OU containing domain controllers, or one `AddMember` over a Tier-0 group, is the finding. Resolving every group in the domain is not required to prove it.
5. **State the proof.** Proof is the ACE on the container or group, the inheritance flags, and the list of Tier-0 objects inside that container or the group's effective access. Name the exact objects, not the container alone.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `AddMember` on a privileged group | Proves the trustee can join the group and inherit its access, which is the shortest path to that group's rights; any AD. |
| `WriteProperty` on an OU with `ContainerInherit` | Proves rights over every current and future child object, so the exposure grows without further changes; any AD. |
| Nested group with no direct members | Proves that a membership review of direct members alone would miss the path; any AD. |
| `CreateChild` on an OU | Proves the trustee can create objects in the container, which combined with a permissive default ACL yields ownership of new objects; any AD. |
| `ms-DS-MachineAccountQuota` above zero | Proves any domain user can create computer objects, which is the precondition for several RBCD paths; default is 10 on unmodified domains. |

## Worked Contrast

**Weak configuration — an application support group can add members to a group with local admin on servers:**

```powershell
$acl = Get-Acl 'AD:CN=Server Admins,OU=Groups,DC=corp,DC=example'
$acl.Access | Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty' -and $_.ObjectType -eq [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2' }
# the group can add itself to Server Admins, which holds local admin on every member server
```

**Hardened configuration — membership changes restricted to a tier-0 group with an approval workflow:**

```powershell
$path = 'AD:CN=Server Admins,OU=Groups,DC=corp,DC=example'
$acl = Get-Acl $path
$acl.Access | Where-Object {
    $_.ObjectType -eq [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2' -and
    $_.IdentityReference -notmatch 'Domain Admins'
} | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
Set-Acl -Path $path -AclObject $acl
# verification: the member-write ACE now names only tier-0 groups
```

**Why this matters:** the member attribute is the object of the ACE, so the control is that property's trustee list, and the verification is re-reading the ACE rather than checking the group's members afterwards.

## When It Is NOT This Issue

- **A group with no effective access.** `AddMember` over a group that grants nothing is not an escalation edge; resolve the group's rights before reporting it.
- **A nested group already containing only the trustee.** If the trustee is already transitively a member, the `AddMember` right adds nothing; check current membership first.
- **An OU that receives no privileged objects.** A writable OU for contractor laptops is a design choice; the finding begins when a Tier-0 object lands in it or can be moved into it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-acl-and-delegation-abuse-group-and-ou-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-acl-and-delegation-abuse-group-and-ou-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-acl-and-delegation-abuse-group-and-ou-abuse
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
- [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-acl-and-delegation-abuse-group-and-ou-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1098`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/hacker_recipes (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
