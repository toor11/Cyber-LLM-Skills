---
name: active-directory-acl-and-delegation-abuse
description: "Exploits misconfigured AD permissions and delegation: GenericAll, WriteDACL, ForceChangePassword, AddMember, unconstrained and constrained delegation, and resource-based constrained delegation. Use when reviewing ACLs or delegation settings."
family: network-ad-and-endpoint
tier: core
triggers: ["acl abuse", "ad acl", "genericall", "writedacl", "rbcd", "unconstrained delegation", "ad permissions"]
cwe: [CWE-269]
owasp: []
attack: [T1098]
capec: [CAPEC-122]
related: [active-directory-acl-genericall-writedacl, active-directory-acl-targeted-kerberoast-shadow-credentials, active-directory-acl-and-delegation-abuse-group-and-ou-abuse, network-recon-and-port-scanning]
---

# Active Directory Acl and Delegation Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Active Directory permissions are themselves the access-control system, so a single ACE on the right object is equivalent to a privilege. `GenericAll` over a user permits a password reset; `WriteDACL` permits granting yourself anything; `WriteProperty` on `msDS-KeyCredentialLink` permits authentication as the target. The methodology is therefore a graph problem with an unusual property: the edges are explicit, auditable, and often granted for a legitimate reason that has since lapsed.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the ACE grants full control over an object **THEN** use [`active-directory-acl-genericall-writedacl`](../active-directory-acl-genericall-writedacl/SKILL.md)
2. **IF** the ACE is over a group or an OU **THEN** use [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](../active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md)
3. **IF** the edge targets a credential-bearing attribute **THEN** use [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md)
4. **IF** the edge is a delegation flag rather than an ACE **THEN** switch to [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `active-directory-acl-and-delegation-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Full control or DACL write over an object | [`active-directory-acl-genericall-writedacl`](../active-directory-acl-genericall-writedacl/SKILL.md) | What full control and DACL write permit |
| Group membership or OU-level rights | [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](../active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md) | Inheritance and nested membership |
| Attribute writes on credential-bearing properties | [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) | SPN and key-credential writes |
| Delegation flags rather than ACEs | [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) | S4U and RBCD semantics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the security descriptor, not the group name.** Every claim starts with the object's DACL: trustee SID, access mask, ACE type, inheritance flags. A group name in a report is a summary; the ACE is the evidence, and it is also the only thing that can be remediated.
2. **Determine whether the right is inherited or explicit.** An inherited ACE comes from a parent container and is usually intentional at that level; an explicit ACE on a single object is more often a one-off grant that outlived its purpose. The remediation differs: remove the ACE, or move the object out of the container.
3. **Trace only edges that reach a Tier-0 asset.** Define Tier-0 first, then walk. An `GenericAll` over a workstation is noise; over a domain controller it is the finding. The graph is large precisely because most of it does not matter.
4. **Baseline against a freshly promoted domain.** A new domain's default ACL set is the reference. Deviation on who holds `WriteDACL` over an OU, or `GenericAll` over a privileged group, is the finding; parity is the default.
5. **State the proof and the stop condition.** Proof is the ACE, the object, and the terminal Tier-0 asset, all read from live descriptors. Stop at the first complete path; a second path adds remediation work, not evidence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `GenericAll` ACE on a user object | Proves the trustee can reset the password, write any attribute, and change the DACL; any AD. |
| `WriteDACL` on an OU | Proves the trustee can grant itself any right over every object in the OU, including newly created ones; any AD. |
| `WriteProperty` scoped to a schema GUID | Proves a narrow but sufficient right, such as writing `servicePrincipalName` or `msDS-KeyCredentialLink`; any AD. |
| `ForceChangePassword` extended right | Proves password reset without full control, the classic helpdesk delegation that becomes an escalation edge; any AD. |
| `AllowedToAct` on a computer object | Proves RBCD write capability, whose effect depends on whether the trustee can also authenticate as a user; any AD with RBCD. |

## Worked Contrast

**Weak configuration — an explicit GenericAll granted to a service desk group over an OU of servers:**

```powershell
$acl = Get-Acl 'AD:OU=Servers,DC=corp,DC=example'
$acl.Access | Where-Object { $_.IdentityReference -match 'ServiceDesk' }
# the group can reset any computer account password in the OU, including DCs if present
```

**Hardened configuration — narrow delegated rights scoped to the objects that genuinely need them:**

```powershell
$acl = Get-Acl 'AD:OU=Servers,DC=corp,DC=example'
$acl.Access | Where-Object { $_.IdentityReference -match 'ServiceDesk' } | ForEach-Object {
    $acl.RemoveAccessRule($_) | Out-Null
}
Set-Acl -Path 'AD:OU=Servers,DC=corp,DC=example' -AclObject $acl
# then delegate only 'Reset Password' on a child OU that excludes Tier-0 objects
# verification: the DACL read shows no GenericAll for the service desk group
```

**Why this matters:** the exposure is one ACE, and its blast radius is the container it inherits into, so remediation is removing that ACE and re-delegating narrowly rather than trusting a process change.

## When It Is NOT This Issue

- **Default ACEs on a freshly promoted domain.** Domain Admins and Enterprise Admins hold broad rights by design; reporting the default set as a finding wastes remediation effort.
- **An ACE that grants only read.** Read access to most attributes is default for Authenticated Users; only rights that change state constitute an edge.
- **An edge to a disabled or unreachable object.** A path terminating at a disabled account or an offline host is not usable; check the object's state before ranking.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-acl-and-delegation-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-acl-and-delegation-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-acl-and-delegation-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1098]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-acl-genericall-writedacl`](../active-directory-acl-genericall-writedacl/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](../active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-acl-and-delegation-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1098`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/oxdf (9), CYBER_CPT/github_security_md (5), CYBER_CPT/sigmahq (1), CYBER_CPT/hacktricks (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 10 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
