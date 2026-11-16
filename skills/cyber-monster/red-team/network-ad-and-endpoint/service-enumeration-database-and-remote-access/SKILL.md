---
name: service-enumeration-database-and-remote-access
description: Database and remote access service enumeration. Covers MSSQL, MySQL, PostgreSQL, RDP, WinRM, VNC and SSH enumeration for version, auth mode and accessible accounts. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["mssql enum", "rdp enum", "winrm enum", "mysql enum", "remote access enumeration"]
cwe: [CWE-284]
owasp: []
attack: [T1046]
capec: [CAPEC-116]
related: [service-enumeration, service-enumeration-smb-and-netbios, service-enumeration-ldap-and-directory, service-enumeration-snmp-and-infrastructure]
parent: service-enumeration
---

# Service Enumeration Database and Remote Access - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Database and remote-access services expose their authentication mode before any credential is used: a pre-login packet names the SQL Server instance and encryption preference, a MySQL handshake names the protocol version and auth plugin, an RDP negotiation names the requested security protocol and whether NLA is required. These pre-authentication exchanges are the honest evidence for 'how is this service exposed', because they exist whether or not you hold a credential.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`service-enumeration`](../service-enumeration/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the service is MSSQL or Oracle and the host is a Windows member **THEN** read the pre-login exchange first; the instance name and encryption flag come back without authentication
3. **IF** the service is RDP and the question is NLA **THEN** the X.224 negotiation reply names the selected protocol; NLA required versus not is the finding
4. **IF** a credential is available and the question becomes authorisation **THEN** keep that result separate from the pre-auth result, and cite both
5. **IF** the port is a pooler or proxy **THEN** resolve what is behind it before attributing a version, since PgBouncer and ProxySQL answer on behalf of the database
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `service-enumeration-database-and-remote-access` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Host-level enumeration of the same server | [`service-enumeration`](../service-enumeration/SKILL.md) | General protocol and version method |
| RDP session behaviour and shadowing | [`windows-lateral-movement-rdp-and-session-abuse`](../windows-lateral-movement-rdp-and-session-abuse/SKILL.md) | Session-level semantics after authentication |
| The database holds credentials the estate uses | [`credential-dumping`](../credential-dumping/SKILL.md) | Credential material, not service exposure |
| Management interface on a segmentation boundary | [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) | Rule evidence for the management path |
| Need the class-level branch table first | [`service-enumeration`](../service-enumeration/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the pre-authentication handshake.** Capture the first exchange in both directions. MSSQL pre-login returns the instance name, version and `ENCRYPT_OFF/ON` requirement; MySQL's initial handshake returns the server version and auth plugin; RDP's X.224 reply returns the chosen security protocol.
2. **Choose the branch by what the handshake says.** If the server demands encryption, a plaintext probe will fail for a TLS reason rather than a credential reason, and that distinction changes the finding. If it accepts plaintext, the exposure includes credential transit.
3. **Differential against a hardened instance.** A reference instance with forced encryption and NLA required is the baseline. The assessed host deviating on either flag is the finding, expressed as a configuration state rather than a version number.
4. **Stop at the handshake.** One pre-auth exchange proves authentication mode. Attempting logins, enumerating databases, or iterating credentials converts a configuration assessment into an access attempt and is outside non-destructive verification.
5. **State the proof.** Exposure is proven by the pre-auth reply field itself: `ENCRYPT_NOT_SUP` for plaintext-allowed MSSQL, a MySQL handshake with `mysql_native_password`, or an RDP negotiation reply without `PROTOCOL_HYBRID` when NLA is expected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| MSSQL pre-login `ENCRYPT_OFF` | Proves the instance accepts an unencrypted login exchange, so credentials cross the wire in a recoverable form; MSSQL on Windows and Linux. |
| MySQL handshake `auth_plugin_name` | Proves which authentication plugin the server offers and therefore whether the credential exchange is challenge-based or cleartext; MySQL and MariaDB. |
| RDP X.224 reply `selectedProtocol` | Proves whether NLA (CredSSP) is required, which decides whether pre-auth attacks against the logon screen are reachable; Windows RDP. |
| `nmap -p1433 --script ms-sql-info` | Proves instance name, version and port from the pre-login exchange without a login attempt; MSSQL. |
| `nmap -p3389 --script rdp-ntlm-info` | Proves the target's NetBIOS, DNS and OS build from the NLA handshake, which is metadata exposure in itself; Windows RDP. |

## Worked Contrast

**Weak configuration — MSSQL accepting unencrypted logins and RDP without NLA:**

```powershell
# SQL Server: encryption optional; RDP: NLA not required
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer' `
    -Name ForceEncryption -Value 0
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name UserAuthentication -Value 0
```

**Hardened configuration — forced encryption and NLA required:**

```powershell
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer' `
    -Name ForceEncryption -Value 1
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name UserAuthentication -Value 1
# pre-login now returns ENCRYPT_ON, and the RDP reply requires PROTOCOL_HYBRID
```

**Why this matters:** both findings live in the pre-authentication negotiation, so the same handshake after the change is the verification and no credential is needed to prove the fix.

## When It Is NOT This Issue

- **Load balancer or pooler answering.** A single MySQL handshake version across ten addresses, or an MSSQL instance name that does not match the host, means a proxy is terminating the protocol.
- **RDP behind a gateway.** An RD Gateway or RD Web front end negotiates TLS on 443 and never exposes the host's RDP stack; the host's NLA setting is then invisible from outside.
- **Database on a loopback-only listener.** A version string returned through an SSH tunnel proves the tunnel, not internet exposure; state the path in the finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `service-enumeration-database-and-remote-access` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `service-enumeration-database-and-remote-access` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: service-enumeration-database-and-remote-access
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
- [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration-snmp-and-infrastructure`](../service-enumeration-snmp-and-infrastructure/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `service-enumeration-database-and-remote-access` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1046`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/oxdf (7), CYBER_CPT/github_security_md (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
