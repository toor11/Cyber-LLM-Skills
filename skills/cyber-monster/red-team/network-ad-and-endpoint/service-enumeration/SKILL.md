---
name: service-enumeration
description: "Enumerates discovered services for users, shares, versions and configuration: SMB, LDAP, NFS, RDP, WinRM, MSSQL, FTP, SSH, SNMP and web management interfaces. Use once open ports are known."
family: network-ad-and-endpoint
tier: core
triggers: ["service enumeration", "smb enum", "snmp enum", "nfs enum", "ftp enum", "enum4linux"]
cwe: [CWE-284]
owasp: []
attack: [T1046]
capec: [CAPEC-116]
related: [service-enumeration-smb-and-netbios, service-enumeration-ldap-and-directory, service-enumeration-database-and-remote-access, network-recon-and-port-scanning]
---

# Service Enumeration - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Enumeration converts an open port into a described service: product, version, configuration, and the identities or shares it exposes. The technique is protocol-specific because each protocol has its own unauthenticated surface — an SMB negotiation, an LDAP root DSE read, an SNMP sysDescr query — and its own notion of a benign request. What makes enumeration defensible rather than speculative is that each claim is backed by a response that only that service could have produced.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the port is unknown or unreachable **THEN** go back to [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) and establish reachability first
2. **IF** the service is SMB or NetBIOS **THEN** use [`service-enumeration-smb-and-netbios`](../service-enumeration-smb-and-netbios/SKILL.md) for negotiation, signing and share semantics
3. **IF** the service is a directory **THEN** use [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) so root DSE and anonymous bind rules are applied
4. **IF** the service is database or remote access **THEN** use [`service-enumeration-database-and-remote-access`](../service-enumeration-database-and-remote-access/SKILL.md) for authentication-mode evidence
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `service-enumeration` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| SMB, NetBIOS, signing and shares | [`service-enumeration-smb-and-netbios`](../service-enumeration-smb-and-netbios/SKILL.md) | Negotiation dialect and signing state are the finding |
| LDAP, root DSE, anonymous bind | [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) | Directory metadata without credentials |
| SNMP, IPMI, infrastructure agents | [`service-enumeration-snmp-and-infrastructure`](../service-enumeration-snmp-and-infrastructure/SKILL.md) | Community strings and management planes |
| Database and remote-access services | [`service-enumeration-database-and-remote-access`](../service-enumeration-database-and-remote-access/SKILL.md) | Authentication mode and exposed administrative surfaces |
| Banner is ambiguous | [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) | Re-probe before attributing a product |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the protocol before the product.** Send the smallest valid request for the port's expected protocol and read the reply structure. A product guess from a banner string is weak evidence; a protocol-correct response is strong evidence because it constrains what the peer can be.
2. **Pick the branch by authentication state.** Unauthenticated enumeration first: negotiation, root DSE, public shares, anonymous bind. Only then, with authorised credentials, authenticated enumeration. Mixing them destroys the differential, because you can no longer say what an anonymous attacker would have seen.
3. **Baseline a stock instance of the same product.** Compare the target's responses against a default install in the lab. Differences in dialect, supported versions or exposed metadata are the finding; sameness is a reason to stop, not to keep enumerating.
4. **Name the stop condition.** Stop at the first response that proves the claim: one share listing, one root DSE, one sysDescr. Continued enumeration after proof adds noise and risk without adding evidence, and on fragile services it adds outage risk.
5. **Write the proof standard.** A service claim needs a protocol response, the exact request that produced it, and a version or configuration attribute read from that response. Anything inferred from a port number alone is a hypothesis and belongs in the report as one.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `nmap -sV --version-intensity 5 -p 445` | Proves product and version from protocol probes rather than a banner grab; Linux. Low intensity keeps it to well-formed requests. |
| SMB negotiate dialect reply | Proves the SMB version range the host accepts and whether signing is required; Windows and Samba. This is configuration evidence, not just a version string. |
| LDAP root DSE read | Proves the directory's naming contexts, supported controls and functional level without authentication; any LDAP server. |
| `snmpwalk -v2c -c public sysDescr` | Proves whether a default community string is answered and what the device reports about itself; network infrastructure. |
| `rpcclient -U '' -N host` | Proves which MSRPC interfaces accept an anonymous session; Samba and Windows. |

## Worked Contrast

**Weak configuration — null sessions and anonymous enumeration left enabled:**

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 0
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 0
# anonymous SID and share enumeration succeeds before any credential is supplied
```

**Hardened configuration — anonymous access refused, guest disabled:**

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1
Disable-LocalUser -Name Guest
# re-run the anonymous probe: access denied, with the same request
```

**Why this matters:** the exposure is the anonymous session itself, so the evidence pair is identical requests before and after the LSA change, not a version string.

## When It Is NOT This Issue

- **Scanner fingerprint match only.** A version string scraped from a banner can belong to a proxy, a honeypot, or an old cached page; confirm with a protocol exchange that the claimed product must answer.
- **Authenticated data mistaken for anonymous.** Shares or users enumerated with a supplied credential say nothing about anonymous exposure; keep the two result sets separate.
- **Default service identity is not a finding.** A service running as `NT AUTHORITY\NETWORK SERVICE` or `www-data` is normal; only the permissions it actually holds matter.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `service-enumeration` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `service-enumeration` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: service-enumeration
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1046]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`service-enumeration-smb-and-netbios`](../service-enumeration-smb-and-netbios/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration-database-and-remote-access`](../service-enumeration-database-and-remote-access/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `service-enumeration` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1046`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/L5/ctf_search (6), CYBER_CPT/oxdf (6), OffsecCyber (2), SecEval/attck (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
