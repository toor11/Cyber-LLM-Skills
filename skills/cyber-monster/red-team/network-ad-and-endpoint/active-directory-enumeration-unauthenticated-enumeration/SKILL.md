---
name: active-directory-enumeration-unauthenticated-enumeration
description: Unauthenticated AD enumeration. Covers null session and anonymous LDAP discovery, domain naming context retrieval and unauthenticated share and user enumeration. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["unauthenticated ad enum", "null session ldap", "anonymous domain enum"]
cwe: [CWE-284]
owasp: []
attack: [T1087]
capec: [CAPEC-116]
related: [active-directory-enumeration, active-directory-enumeration-authenticated-enumeration, active-directory-enumeration-gpo-and-administrative-discovery, network-recon-and-port-scanning]
parent: active-directory-enumeration
---

# Active Directory Enumeration Unauthenticated Enumeration - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Unauthenticated directory enumeration covers everything a network-adjacent attacker learns with no credential: the domain name from DNS SRV records, the naming context from the LDAP root DSE, the host's role from NetBIOS suffixes, and any object data a null session or anonymous bind still returns. Modern Windows defaults close most of this, so the finding is usually a specific deviation — an anonymous bind still permitted, a null session reaching SAMR, or an LDAP attribute readable to Everyone.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** you hold any domain credential **THEN** switch to [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md); mixing anonymous and authenticated results destroys the differential
3. **IF** only DNS answers **THEN** enumerate SRV records first; the domain name and DC list come back without touching LDAP
4. **IF** LDAP answers but the bind fails **THEN** a root DSE read succeeding with a failed simple bind is a normal, hardened state and not a finding by itself
5. **IF** SMB answers with a null session **THEN** probe SAMR and LSA separately, since one may be open while the other is closed
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-enumeration-unauthenticated-enumeration` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A credential becomes available | [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) | Object and ACL collection with an identity |
| Directory protocol questions | [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) | Root DSE and bind semantics |
| SMB-specific anonymous surface | [`service-enumeration-smb-and-netbios`](../service-enumeration-smb-and-netbios/SKILL.md) | Null session and share semantics |
| Domain name is known and trusts matter | [`active-directory-trust-and-forest-abuse`](../active-directory-trust-and-forest-abuse/SKILL.md) | Inter-realm behaviour |
| Need the class-level branch table first | [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Start with DNS, which is almost always open.** Query `_ldap._tcp.dc._msdcs.<domain>` and `_kerberos._tcp.<domain>` SRV records. This yields the domain name, the DC hostnames and the site topology with no authentication, and it establishes scope before any directory protocol is touched.
2. **Read the root DSE and record exactly what it returns.** `namingContexts`, `supportedSASLMechanisms`, `supportedControl` and `dnsHostName`. This is served without authentication on every AD domain controller and is not a finding; it is the reference for what an anonymous client can see.
3. **Test the anonymous branches one at a time.** Anonymous LDAP bind, null SMB session, SAMR enumeration and LSA policy read are four separate controls with four separate registry or policy settings. Test each and record the exact error, because `access denied` and `strongerAuthRequired` mean different things.
4. **Differential against a hardened 2025 functional-level domain.** A current domain refuses anonymous bind, disables the guest account, and restricts anonymous SID translation. Any successful anonymous read on the assessed domain is then provably a deviation.
5. **Stop at the first anonymous read of object data.** The root DSE is metadata; a readable `sAMAccountName` list is the finding. Once an anonymous query returns an object, stop and record the query, the base DN and the returned attributes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `_ldap._tcp.dc._msdcs.<domain>` SRV record | Proves the domain name and DC inventory without credentials; any DNS resolver in the forest. |
| `nltest /dsgetdc:<domain>` | Proves domain discovery and the DC's site and flags from a Windows host that can query DNS or WINS. |
| `rpcclient -U '' -N dc01 -c 'dsroledominfo'` | Proves whether a null session reaches the SAMR or LSARPC interface; Windows DC with legacy RPC exposure. |
| `Get-ADDomain -Server dc01 -Credential $null` | Proves whether a Windows client can read domain metadata without a credential; Windows. Usually fails on patched domains, which is the expected baseline. |
| `ldapsearch -x -H ldap://dc01 -b '' -s base` | Proves the anonymous LDAP surface and the exact error when anonymous bind is refused; any LDAP server. |

## Worked Contrast

**Weak configuration — anonymous LDAP bind and null SMB session both permitted:**

```text
# dsHeuristics does not set the anonymous-deny bit, and the guest account is enabled
# result: an unauthenticated host reads naming contexts and enumerates domain users
ldapsearch -x -H ldap://dc01.corp.example -b 'DC=corp,DC=example' '(objectClass=user)' sAMAccountName
```

**Hardened configuration — anonymous bind refused, guest disabled, anonymous SID translation blocked:**

```text
# directory: set dsHeuristics anonymous-deny bit on the Directory Service object
# host: RestrictAnonymous=1 and RestrictAnonymousSAM=1, Guest disabled
ldapsearch -x -H ldap://dc01.corp.example -b 'DC=corp,DC=example' '(objectClass=user)' sAMAccountName
# result: 000004DC: LdapErr: DSID-0C090A5C, a successful bind must be completed
```

**Why this matters:** every anonymous finding is an authorisation state, so the verification is the same query returning an authorisation error rather than data.

## When It Is NOT This Issue

- **Root DSE readability.** It is served by design on every domain controller and contains no object data; reporting it as anonymous enumeration is the most common false positive in this technique.
- **DNS SRV records.** Publishing `_ldap._tcp` is required for domain join and reveals nothing that is not already public inside the estate; it is not a directory exposure.
- **Guest-enabled but no accessible shares.** A guest account that can authenticate but reaches no share is a hygiene finding, not an anonymous-read finding; verify what the session can actually access.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-enumeration-unauthenticated-enumeration` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-enumeration-unauthenticated-enumeration` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-enumeration-unauthenticated-enumeration
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1087]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration-gpo-and-administrative-discovery`](../active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-enumeration-unauthenticated-enumeration` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1087`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/nuclei_templates (2), CYBER_CPT/expku (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
