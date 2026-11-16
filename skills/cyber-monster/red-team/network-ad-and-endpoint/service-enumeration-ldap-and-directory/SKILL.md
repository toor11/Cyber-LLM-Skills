---
name: service-enumeration-ldap-and-directory
description: LDAP and directory service enumeration. Covers anonymous and authenticated LDAP queries, base DN discovery, attribute harvesting and directory schema review. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["ldap enum", "anonymous ldap", "base dn", "directory enumeration"]
cwe: [CWE-284]
owasp: []
attack: [T1046]
capec: [CAPEC-116]
related: [service-enumeration, service-enumeration-smb-and-netbios, service-enumeration-database-and-remote-access, service-enumeration-snmp-and-infrastructure]
parent: service-enumeration
---

# Service Enumeration LDAP and Directory - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Directory enumeration reads the LDAP surface a client can reach before authentication: the root DSE, the supported controls and SASL mechanisms, and whatever the server permits anonymously. Those reads establish the naming context, the functional level in some deployments, and whether anonymous bind is allowed at all. Everything after that is an authorisation question, so the anonymous-versus-authenticated split is the whole methodology rather than a preliminary step.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`service-enumeration`](../service-enumeration/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the port answers but bind fails **THEN** read the root DSE with a base-scope search first; it is served before authentication on most directories
3. **IF** anonymous bind succeeds **THEN** record exactly which attributes are readable anonymously, then stop; that is the finding
4. **IF** you have a low-privileged identity **THEN** move to [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) so ACL and SPN analysis is done properly
5. **IF** LDAPS fails while LDAP succeeds **THEN** suspect a certificate or channel-binding problem and report it as a TLS exposure, not a directory one
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `service-enumeration-ldap-and-directory` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Credentials exist and ACLs matter | [`active-directory-enumeration-authenticated-enumeration`](../active-directory-enumeration-authenticated-enumeration/SKILL.md) | Object ACL and SPN analysis needs a session |
| No credentials at all | [`active-directory-enumeration-unauthenticated-enumeration`](../active-directory-enumeration-unauthenticated-enumeration/SKILL.md) | Naming context and anonymous-bind rules |
| Directory is Active Directory and trusts matter | [`active-directory-trust-and-forest-abuse`](../active-directory-trust-and-forest-abuse/SKILL.md) | Inter-realm behaviour after enumeration |
| Port 389 open on a non-directory device | [`service-enumeration`](../service-enumeration/SKILL.md) | Protocol confirmation before directory claims |
| Need the class-level branch table first | [`service-enumeration`](../service-enumeration/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm LDAP with a base-scope root DSE read.** `-s base -b ''` returns `namingContexts`, `supportedLDAPVersion`, `supportedSASLMechanisms` and `supportedControl`. If that returns nothing, the port is not a directory and every later conclusion would be wrong.
2. **Choose the bind branch deliberately.** Anonymous, simple with a credential, or SASL/Kerberos. Each produces different visibility. Run anonymous first and record its result verbatim, because it defines the pre-authentication exposure and cannot be reconstructed later.
3. **Differential against a hardened reference directory.** Compare the anonymous attribute set against your lab domain's anonymous set. Extra readable attributes, such as `dnsHostName` or `ms-DS-MachineAccountQuota`, are the actual finding.
4. **Bound the search before it becomes a dump.** Set a size limit and a base DN scoped to one OU, and never page through an entire directory on a production domain controller. The stop condition is the first page that proves readable sensitive attributes.
5. **State the proof.** Anonymous read exposure is proven by an attribute value returned to a base-scope search with no bind. Authenticated exposure is proven by the same attribute plus the identity that could read it and the ACL entry that granted it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ldapsearch -x -H ldap://host -s base -b ''` | Proves the directory is LDAP and names its contexts, controls and SASL mechanisms; any LDAPv3 server. |
| `nmap -p389 --script ldap-rootdse` | Proves the same without a client install and reports the server's `supportedLDAPVersion`; any directory. |
| `ldapsearch -x -H ldap://host -b 'DC=corp,DC=example' -s one '(objectClass=*)'` | Proves what an anonymous client can read in a single level, and therefore the size of the pre-auth surface. |
| `netexec ldap host -u "" -p "" --query '(objectClass=*)' ''` | Proves anonymous search against AD specifically, including whether the server returns `operationsError` instead of data. |
| `openssl s_client -connect host:636` | Proves whether LDAPS is offered and which certificate and CA chain it presents. |

## Worked Contrast

**Weak configuration — anonymous LDAP bind permitted with broad read on the directory root:**

```text
# dsHeuristics left at default with anonymous read on the domain NC
# an unauthenticated client can read user, group and computer objects
ldapsearch -x -H ldap://dc01.corp.example -b 'DC=corp,DC=example' -s one '(objectClass=user)' sAMAccountName
```

**Hardened configuration — anonymous bind refused, authenticated read only:**

```text
# directory-side control: deny anonymous LDAP operations
# dsHeuristics value 0000002 (anonymous access denied) on the Directory Service object
ldapsearch -x -H ldap://dc01.corp.example -b 'DC=corp,DC=example' -s one '(objectClass=user)' sAMAccountName
# result: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed
```

**Why this matters:** the exposure is decided by the anonymous-bind policy on the directory service object, so the same search before and after is the only honest verification.

## When It Is NOT This Issue

- **Root DSE read mistaken for anonymous data access.** Root DSE is served by design and contains no user data; reporting it as an anonymous-read finding is a false positive that erodes trust in the rest of the report.
- **Global Catalog on 3268 answering differently from 389.** The GC is a partial replica with its own ACL behaviour; a result from one does not describe the other.
- **Proxy or load balancer in front of the directory.** If `supportedControl` and vendor strings change between two consecutive queries, you are talking to more than one backend.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `service-enumeration-ldap-and-directory` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `service-enumeration-ldap-and-directory` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: service-enumeration-ldap-and-directory
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1046]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration-smb-and-netbios`](../service-enumeration-smb-and-netbios/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration-database-and-remote-access`](../service-enumeration-database-and-remote-access/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration-snmp-and-infrastructure`](../service-enumeration-snmp-and-infrastructure/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `service-enumeration-ldap-and-directory` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1046`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/oxdf (6), CYBER_CPT/L5/ctf_search (3), CYBER_CPT/sigmahq (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
