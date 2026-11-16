---
name: windows-privilege-escalation-credential-and-config-exposure
description: Windows credential and configuration exposure. Covers unattended install files, registry autologon, saved RDP and PuTTY sessions, group policy preferences cpassword and local config secrets. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["unattended xml", "autologon registry", "cpassword", "saved rdp", "config credentials"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [windows-privilege-escalation, windows-privilege-escalation-token-and-privilege-abuse, windows-privilege-escalation-service-and-path-flaws, windows-privilege-escalation-uac-bypass]
parent: windows-privilege-escalation
---

# Windows Privilege Escalation Credential and Config Exposure - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md)

## Mechanism and Preconditions

Windows deployments leave credential material in predictable places: unattended installation files with base64-encoded local account passwords, Group Policy Preferences files with a historically published AES key, registry values holding service account passwords, and configuration files for applications that need to authenticate. None of these requires a vulnerability, only read access. The methodology is to enumerate the file and registry locations that hold secrets, prove readability with the current token, and state which account each secret belongs to.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** an `unattend.xml` or `sysprep.inf` is present **THEN** the `Password` element holds a base64-encoded local account password; check whether the account still exists and is enabled
3. **IF** a `Groups.xml` exists under SYSVOL **THEN** the `cpassword` is encrypted with a published key, so it is effectively plaintext to any domain user
4. **IF** a service registry key contains a `Password` value **THEN** the value is often cleartext and readable by any principal with read on the key
5. **IF** the file is readable but the account is disabled **THEN** the finding is the exposure, but the impact is limited; state both
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `windows-privilege-escalation-credential-and-config-exposure` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The material is a DPAPI blob | [`credential-dumping-dpapi-and-secret-stores`](../credential-dumping-dpapi-and-secret-stores/SKILL.md) | Decryption requires a user or system context |
| The material is in LSASS memory | [`credential-dumping-lsass-and-memory`](../credential-dumping-lsass-and-memory/SKILL.md) | Process access rather than file access |
| The material is a certificate with a private key | [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) | Certificate-based authentication |
| The file is writable as well as readable | [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) | Write access on a loaded path |
| Need the class-level branch table first | [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the standard credential-bearing locations.** `unattend.xml` and `sysprep.inf` under `%WINDIR%\Panther` and `%WINDIR%\System32\Sysprep`; `Groups.xml` under SYSVOL; `web.config` and `appsettings.json` for application secrets; service keys under `HKLM\SYSTEM\CurrentControlSet\Services`. Each has a different owner and a different remediation.
2. **Prove readability with the current token.** `icacls` gives the ACL and `Get-Content` proves the read. A file with a restrictive ACL is not a finding regardless of its content, and an inaccessible file cannot be reported as exposed.
3. **Map each secret to an account and its current state.** An `unattend.xml` password for a local account that was deleted is a hygiene finding; for an enabled local administrator it is a boundary crossing. Read the account state before assigning severity.
4. **Baseline against a clean build.** A properly decommissioned image has no `unattend.xml` in Panther, no `cpassword` in SYSVOL, and no cleartext service passwords. Deviation is the finding, and it is directly remediable.
5. **State the proof.** Proof is the readable file or registry value, the ACL that permits the read, and the account the secret belongs to with its current enabled state. Reading the secret is the proof; using it is a separate authorised step.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `unattend.xml` `Password` element | Proves a base64-encoded local account password readable by any principal with access to `%WINDIR%\Panther`; Windows images deployed with unattend files. |
| SYSVOL `Groups.xml` `cpassword` | Proves a Group Policy Preferences credential encrypted with a published AES key, readable by any domain user; AD domains with legacy GPP. |
| `HKLM\...\Services\<svc>\Password` | Proves a cleartext or weakly protected service account password; Windows hosts with services running as named accounts. |
| `web.config` `connectionStrings` | Proves database credentials in a file readable by the application pool identity and often by Users; IIS-hosted applications. |
| `Get-ChildItem -Recurse` on `%WINDIR%\Panther` | Proves which unattend artefacts remain after imaging; Windows. |

## Worked Contrast

**Weak configuration — an unattend file with a base64 local-admin password left in Panther:**

```powershell
Get-ChildItem C:\Windows\Panther\unattend.xml | Select-Object FullName,Length
# <Password><Value>BASE64VALUE</Value><PlainText>false</PlainText></Password>
# BUILTIN\Users has read on the file, and the account it names is still enabled
```

**Hardened configuration — unattend artefacts removed and the account password rotated:**

```powershell
Remove-Item C:\Windows\Panther\unattend.xml -Force
Remove-Item C:\Windows\System32\Sysprep\unattend.xml -Force -ErrorAction SilentlyContinue
# rotate the local account password if the file was readable for any period
# verification: the file is absent and the local account password was changed after the removal
```

**Why this matters:** the exposure is a readable file holding a live secret, so the control is removal plus rotation, and removal alone is insufficient because the secret was already exposed.

## When It Is NOT This Issue

- **A secret for a deleted or disabled account.** The file exposure is real but the impact is historical; state the account state so the reader can judge it.
- **A configuration file with a placeholder or a reference.** `connectionString` pointing at a managed identity or a key vault reference contains no secret; check before reporting.
- **A password-protected archive.** An encrypted backup on disk is not readable credential material; the finding would need the decryption key.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `windows-privilege-escalation-credential-and-config-exposure` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `windows-privilege-escalation-credential-and-config-exposure` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: windows-privilege-escalation-credential-and-config-exposure
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1068]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) - Blue Detection/Defense Counterpart
- [`windows-privilege-escalation`](../windows-privilege-escalation/SKILL.md) - Network, Active Directory and Endpoint (flagship)
- [`windows-privilege-escalation-token-and-privilege-abuse`](../windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-service-and-path-flaws`](../windows-privilege-escalation-service-and-path-flaws/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-uac-bypass`](../windows-privilege-escalation-uac-bypass/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-privilege-escalation-credential-and-config-exposure` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/nuclei_templates (3), CYBER_CPT/atomic_red_team (3), CYBER_CPT/mitre_attack_enterprise (1), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
