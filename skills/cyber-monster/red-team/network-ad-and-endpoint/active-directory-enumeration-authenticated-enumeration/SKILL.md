---
name: active-directory-enumeration-authenticated-enumeration
description: Authenticated AD enumeration and path mapping. Covers BloodHound collection, ACL path analysis, session and privilege mapping as a low-privileged domain user. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["bloodhound collection", "ad path mapping", "acl path", "low priv enumeration"]
cwe: [CWE-284]
owasp: []
attack: [T1087]
capec: [CAPEC-116]
related: [active-directory-enumeration, active-directory-enumeration-unauthenticated-enumeration, active-directory-enumeration-gpo-and-administrative-discovery, network-recon-and-port-scanning]
parent: active-directory-enumeration
---

# Active Directory Enumeration Authenticated Enumeration - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Authenticated enumeration reads what a domain identity is allowed to see: object attributes, security descriptors, SPNs, and session data. The graph is an artefact of default permissions plus deliberate delegation, and the technique's value comes from separating the two. Object ACLs are read through LDAP with a security-descriptor control, local group membership through SAMR, and logon sessions through the NetSession or Win32_LogonSession interfaces, each of which has its own access check.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the credential is a machine account rather than a user **THEN** collect with that identity separately; machine accounts often read attributes a user cannot, and the graphs must not be merged
3. **IF** the estate uses gMSA or Windows Server 2025 dMSA **THEN** read `msDS-ManagedPassword` readers and `msDS-ManagedAccountPrecededByLink` early, since both are direct escalation edges
4. **IF** SPNs are the interesting surface **THEN** hand the SPN list to [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) rather than reasoning about tickets here
5. **IF** ACLs are collected and need interpretation **THEN** hand the edge list to [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-enumeration-authenticated-enumeration` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| No credential at all | [`active-directory-enumeration-unauthenticated-enumeration`](../active-directory-enumeration-unauthenticated-enumeration/SKILL.md) | Anonymous surface before this step |
| ACL edges need abuse semantics | [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) | What each right actually permits |
| SPN-bearing accounts found | [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) | Ticket request and offline recovery path |
| GPO and delegated admin questions | [`active-directory-enumeration-gpo-and-administrative-discovery`](../active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md) | Policy linkage and delegated rights |
| Need the class-level branch table first | [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Record the identity, its groups and its logon rights.** The collecting account's token decides what every later query can read. Capture `tokenGroups` and the account's `userAccountControl` so the report states which identity produced which edge.
2. **Collect LDAP objects and security descriptors together.** Attributes alone give you objects; the descriptor gives you the edges. Request the DACL with the security-descriptor control in the same query, so an edge always has its object and its mask from the same read.
3. **Separate computer, user, gMSA and dMSA classes.** Each class has different interesting attributes: computers have `msDS-AllowedToActOnBehalfOfOtherIdentity`, gMSAs have `msDS-ManagedPassword`, dMSAs have `msDS-ManagedAccountPrecededByLink`, users have `msDS-KeyCredentialLink`. Querying them together buries the escalation edges in noise.
4. **Rank against a Tier-0 definition you wrote down first.** Name the Tier-0 assets before ranking, then keep only edges whose terminal object is in that set. A ranking done after collection tends to be shaped by whatever the graph tool highlights.
5. **Stop at one proven, complete path and state what proved it.** Each hop needs the object DN, trustee SID, access mask and inheritance flag read from the live descriptor. A path whose hops are inferred from group names is a hypothesis and should be labelled as one.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `msDS-KeyCredentialLink` on a user object | Proves the account already has key credentials and who may write the attribute, which is the shadow-credential precondition; AD with Windows Hello for Business or Key Trust. |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer | Proves resource-based constrained delegation is configured and which principals may impersonate to that host; any AD with RBCD. |
| `msDS-ManagedPassword` readers on a gMSA | Proves which principals can retrieve the managed password in cleartext-equivalent form; AD with gMSA. |
| `servicePrincipalName` on user objects | Proves which accounts are kerberoastable and at which encryption types; any AD. |
| `userAccountControl` without `DONT_EXPIRE_PASSWORD` and with `PASSWD_NOTREQD` | Proves password policy exceptions on specific accounts; any AD. |

## Worked Contrast

**Weak configuration — a plain domain user can write msDS-KeyCredentialLink on a Tier-0 account:**

```powershell
# inherited ACE grants Authenticated Users WriteProperty on msDS-KeyCredentialLink
# over an OU that contains privileged accounts
$acl = Get-Acl "AD:OU=Privileged,DC=corp,DC=example"
$acl.Access | Where-Object { $_.ObjectType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063' }
# any domain user can add a key credential and authenticate as the account
```

**Hardened configuration — attribute write removed and delegated only to a named tier-0 group:**

```powershell
$acl = Get-Acl "AD:OU=Privileged,DC=corp,DC=example"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.SecurityIdentifier]'S-1-5-11','WriteProperty','Allow',
    [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063')
$acl.RemoveAccessRule($rule) | Out-Null
Set-Acl -Path "AD:OU=Privileged,DC=corp,DC=example" -AclObject $acl
# verification: the same write returns access denied for a plain domain user
```

**Why this matters:** the edge is a single ACE on the attribute GUID, so the control is that ACE and the verification is re-reading the descriptor and re-running the write attempt.

## When It Is NOT This Issue

- **Default read permissions.** Every authenticated principal can read most attributes; an edge made only of default reads is not a misconfiguration and should be described as the default.
- **Delegation that is intentional and scoped.** A helpdesk group with `Reset Password` on one OU is a designed control; check the scope before reporting it as excess privilege.
- **A path through an account that cannot log on.** `ACCOUNTDISABLE` or a smart-card-only requirement makes the terminal hop unusable; check `userAccountControl` before ranking a path.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-enumeration-authenticated-enumeration` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-enumeration-authenticated-enumeration` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-enumeration-authenticated-enumeration
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
- [`active-directory-enumeration-gpo-and-administrative-discovery`](../active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-enumeration-authenticated-enumeration` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1087`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 19 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (13), CYBER_CPT/sigmahq (5), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 13 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
