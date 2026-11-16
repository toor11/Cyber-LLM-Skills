---
name: active-directory-enumeration-gpo-and-administrative-discovery
description: GPO and administrative control discovery. Covers enumerating group policy objects, delegated control, and identifying accounts and groups with administrative reach. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["gpo enumeration", "delegated control discovery", "admin group discovery"]
cwe: [CWE-284]
owasp: []
attack: [T1087]
capec: [CAPEC-116]
related: [active-directory-enumeration, active-directory-enumeration-unauthenticated-enumeration, active-directory-enumeration-authenticated-enumeration, network-recon-and-port-scanning]
parent: active-directory-enumeration
---

# Active Directory Enumeration Gpo and Administrative Discovery - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Group Policy is an execution path: a GPO linked to an OU applies to every computer and user in it, and write access to a GPO object or its SYSVOL content is equivalent to code execution on those systems. Administrative discovery therefore reads three things together — GPO linkage and contents, the delegated rights over GPO objects, and the local administrative group membership those policies produce. Reading only the policy text misses the delegation that makes it dangerous.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** GPO contents matter but not who can edit them **THEN** read the policy report first; the delegation read is the one that produces a finding
3. **IF** a principal can write to SYSVOL **THEN** treat that as equivalent to write access on the GPO and rank it as a code-execution edge
4. **IF** local admin membership is the question **THEN** collect it per host over SAMR or WinRM rather than inferring it from group policy preferences
5. **IF** an OU is writable by a non-tier-0 group **THEN** that is an ACL question, so pair with [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](../active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-enumeration-gpo-and-administrative-discovery` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The question is object ACLs generally | [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) | Descriptor collection across all classes |
| OU-level write access is the edge | [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](../active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md) | What OU write rights permit |
| A GPO carries a startup script | [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) | Execution artefacts the policy leaves |
| Local admin membership needs reading | [`windows-lateral-movement`](../windows-lateral-movement/SKILL.md) | What the membership enables |
| Need the class-level branch table first | [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate GPO objects and their links before reading content.** `gplink` on each OU gives the applied set, including inherited links. A GPO with no link applies to nothing, and reporting its settings as active is a common error.
2. **Read the GPO's own security descriptor.** The `nTSecurityDescriptor` on the `groupPolicyContainer` object decides who may edit the policy. Combine it with the SYSVOL ACL on the matching `Policies\{GUID}` folder, because edit access can be granted through either.
3. **Check the dangerous policy settings explicitly.** Startup and logon scripts, `Restricted Groups`, `Local Users and Groups` preferences with a stored `cpassword`, and software installation assignments. These are the settings that produce execution or credential material rather than configuration.
4. **Baseline against a default domain policy.** Compare the assessed GPO's edit rights against the default set where only Domain Admins and Enterprise Admins can modify. Deviation to a non-tier-0 group is the finding.
5. **Stop at one GPO whose edit rights reach a Tier-0 OU, and state the proof.** Proof is the GPO's container ACL naming a non-tier-0 trustee with `WriteProperty` or `GenericWrite`, plus the link that places it over privileged objects. A policy setting alone, with no writable path, is a hardening note.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `gplink` on an OU | Proves which GPOs actually apply, including inherited links, which is what makes a policy finding reachable; any AD. |
| `nTSecurityDescriptor` on the GPO container | Proves who may modify the policy object; AD with Group Policy. |
| `cpassword` in `Groups.xml` under SYSVOL | Proves a Group Policy Preferences credential is stored, historically AES-encrypted with a published key; AD domains with legacy GPP. |
| `Get-GPOReport -All -ReportType Xml` | Proves effective settings across every GPO, which is how a startup script or restricted group is found without opening each one; Windows with RSAT. |
| `net group 'Domain Admins' /domain` | Proves current privileged group membership, the terminal set the GPO path must reach; any domain. |

## Worked Contrast

**Weak configuration — a helpdesk group can edit a GPO linked to the domain controllers OU:**

```powershell
$gpo = Get-GPO -Name 'DC Baseline'
$acl = Get-Acl "AD:CN={$($gpo.Id)},CN=Policies,CN=System,DC=corp,DC=example"
$acl.Access | Where-Object IdentityReference -match 'Helpdesk'
# helpdesk can add a startup script that runs as SYSTEM on every DC
```

**Hardened configuration — GPO edit rights restricted to a tier-0 policy administrators group:**

```powershell
$path = "AD:CN={$((Get-GPO -Name 'DC Baseline').Id)},CN=Policies,CN=System,DC=corp,DC=example"
$acl = Get-Acl $path
$acl.Access | Where-Object IdentityReference -match 'Helpdesk' | ForEach-Object {
    $acl.RemoveAccessRule($_) | Out-Null
}
Set-Acl -Path $path -AclObject $acl
# verification: the same ACE read returns no helpdesk trustee
```

**Why this matters:** GPO write access is code execution on the linked scope, so the control is the container ACL and the verification is reading it back rather than testing the policy content.

## When It Is NOT This Issue

- **An unlinked GPO with dangerous settings.** Settings in a GPO that is not linked to any OU are dormant; confirm the link before reporting the setting as active.
- **Blocked inheritance.** An OU with `BlockInheritance` does not receive the parent policy, so a dangerous setting higher in the tree may not apply; read the enforcement and block flags.
- **Loopback processing.** Loopback changes which user policies apply on a computer; a user-side setting may be overridden entirely, so check the loopback mode before claiming effect.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-enumeration-gpo-and-administrative-discovery` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-enumeration-gpo-and-administrative-discovery` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-enumeration-gpo-and-administrative-discovery
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1087]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`active-directory-enumeration-unauthenticated-enumeration`](../active-directory-enumeration-unauthenticated-enumeration/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-enumeration-gpo-and-administrative-discovery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1087`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/sigmahq (3), CYBER_CPT/hacktricks (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
