---
name: active-directory-enumeration
description: "Enumerates Active Directory without credentials or with a low-privileged account: domain and forest discovery, user and group enumeration, SPN discovery, ACL review, trusts and session hunting. Use at the start of any AD assessment."
family: network-ad-and-endpoint
tier: core
triggers: ["active directory enumeration", "ad enum", "bloodhound", "ldap enumeration", "domain enumeration"]
cwe: [CWE-284]
owasp: []
attack: [T1087]
capec: [CAPEC-116]
related: [active-directory-enumeration-unauthenticated-enumeration, active-directory-enumeration-authenticated-enumeration, active-directory-enumeration-gpo-and-administrative-discovery, network-recon-and-port-scanning]
---

# Active Directory Enumeration - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Directory enumeration is an authorisation reading exercise: the domain exposes more to an authenticated low-privileged principal than most teams expect, and the readable surface is decided by default ACLs rather than by intent. The technique walks objects and the links between them, then answers one question — which edges from this principal lead to a Tier-0 asset. Modern estates add two wrinkles: gMSA and dMSA objects store their managed passwords in the directory, and the delegated MSA feature introduced with Windows Server 2025 created a new link attribute that changes what 'successor' means.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** no credential exists yet **THEN** use [`active-directory-enumeration-unauthenticated-enumeration`](../active-directory-enumeration-unauthenticated-enumeration/SKILL.md) so anonymous surfaces stay separate from authenticated ones
2. **IF** a low-privileged domain credential is in hand **THEN** use [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) for object, ACL and SPN collection
3. **IF** the estate has GPOs and delegated administration **THEN** use [`active-directory-enumeration-gpo-and-administrative-discovery`](../active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md) to read policy and delegated rights
4. **IF** collection is finished and paths need ranking **THEN** hand the edge list to [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) rather than re-collecting
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `active-directory-enumeration` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| No credentials, only network reachability | [`active-directory-enumeration-unauthenticated-enumeration`](../active-directory-enumeration-unauthenticated-enumeration/SKILL.md) | Null session, anonymous LDAP and naming-context discovery |
| One low-privileged identity available | [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) | Object, ACL and session collection with an identity |
| Policy and delegation need reading | [`active-directory-enumeration-gpo-and-administrative-discovery`](../active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md) | GPO linkage and delegated rights |
| Paths are known and need exploitation reasoning | [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) | Edge semantics and abuse preconditions |
| Kerberos artefacts need interpreting | [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) | Ticket and SPN behaviour |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix the collecting identity and its group membership.** Record the account, its direct groups, and its nested groups before collecting. Two collections from different identities produce different graphs, and a path found with one identity is not evidence that another could see it.
2. **Choose the collection protocol by what the directory exposes.** LDAP for objects and ACLs, SAMR for local group membership, and the SMB or WinRM session data for logon sessions. Each protocol has its own ACL and its own logging, so the same graph edge can be visible through one and invisible through another.
3. **Baseline the readable attribute set against a hardened reference domain.** Compare which attributes a plain domain user can read in the assessed domain against a lab domain at the same functional level. Extra readable attributes such as `ms-Mcs-AdmPwd` or `msDS-KeyCredentialLink` are the finding, because their readability is the exposure.
4. **Rank edges by Tier-0 reachability, not by count.** A single `GenericAll` over a domain controller outranks fifty edges to workstations. Define Tier-0 as the domain controllers, the krbtgt account, AD CS authorities, Entra Connect and backup infrastructure, then trace only edges that touch those.
5. **Stop when one complete path is proven.** A path is proven when every hop's permission has been read from the object's security descriptor, not inferred from a group name. Continuing to collect after a proven path adds data volume without adding proof.
6. **State the proof standard.** Each hop needs the object DN, the trustee, the access mask and the inheritance flag, read from the live ACL. A graph screenshot is a summary; the security descriptor is the evidence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `bloodhound-python -c All --zip` | Proves the edge set visible to a named identity across LDAP, SAMR and session collection; Windows and Linux collectors. |
| `(objectClass=msDS-GroupManagedServiceAccount)` | Proves whether gMSA objects exist and who may read `msDS-ManagedPassword`, which is a direct credential-read edge; AD with gMSA in use. |
| `msDS-ManagedAccountPrecededByLink` | Proves dMSA migration linkage; on Windows Server 2025 domains this attribute decides which account a dMSA inherits, so its writability is a privilege-escalation edge. |
| `netexec ldap dc -u user -p pass --query '(objectClass=*)'` | Proves attribute readability with a specific identity against the live directory, not a cached graph. |
| `Get-ADUser -Filter * -Properties msDS-KeyCredentialLink` | Proves which accounts already hold key credentials, the state that shadow-credential abuse depends on; Windows with RSAT. |

## Worked Contrast

**Weak configuration — authenticated users can read the gMSA managed password and see every object attribute:**

```powershell
# default: Authenticated Users can read msDS-ManagedPassword on a gMSA
# and can read most user attributes on every object in the domain
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPassword |
    Select-Object Name, @{n='Readers';e={ (Get-Acl "AD:$($_.DistinguishedName)").Access }}
# a plain domain user harvests service-account material without any delegation
```

**Hardened configuration — gMSA password readable only by the intended host principals:**

```powershell
# recreate the gMSA with an explicit PrincipalsAllowedToReadPassword list
New-ADServiceAccount -Name svc_sql -DNSHostName svc_sql.corp.example `
    -PrincipalsAllowedToRetrieveManagedPassword 'SQLHOST01$'
# verification: the same read now returns access denied for a plain domain user
Get-ADServiceAccount svc_sql -Properties msDS-ManagedPassword
```

**Why this matters:** the exposure is a readable attribute, so the control is the reader list on that attribute and the verification is the identical read failing for an identity that is not the host principal.

## When It Is NOT This Issue

- **Graph edges that reflect default permissions only.** Every domain has `Authenticated Users` able to read many attributes; a path that consists solely of default-read edges proves the default, not a misconfiguration.
- **Stale collection data.** A BloodHound dataset older than the last ACL change will show edges that no longer exist; re-read the security descriptor of the specific object before reporting.
- **Tier-0 path that ends in a disabled account.** A path to a disabled or Smart Card-required-for-interactive-logon account is not a usable path; check account control flags before ranking.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-enumeration` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-enumeration` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-enumeration
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1087]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-enumeration-unauthenticated-enumeration`](../active-directory-enumeration-unauthenticated-enumeration/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration-gpo-and-administrative-discovery`](../active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-enumeration` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1087`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 24 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (18), CYBER_CPT/L5/ctf_search (3), CYBER_CPT/sigmahq (2), CYBER_CPT/hacktricks (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
