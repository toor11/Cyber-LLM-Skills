---
name: credential-dumping-dpapi-and-secret-stores
description: DPAPI and application secret stores. Covers DPAPI master key and blob decryption, browser credential stores, Windows Credential Manager and application config secrets. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["dpapi", "credential manager", "browser passwords", "masterkey decrypt"]
cwe: [CWE-522]
owasp: []
attack: [T1003]
capec: [CAPEC-60]
related: [credential-dumping, credential-dumping-lsass-and-memory, credential-dumping-sam-and-ntds, network-recon-and-port-scanning]
parent: credential-dumping
---

# Credential Dumping Dpapi and Secret Stores - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md)

## Mechanism and Preconditions

DPAPI encrypts per-user and per-machine secrets with keys derived from the user's password or the machine account, and stores master keys under the user profile or `%WINDIR%\System32\Microsoft\Protect`. Recovering a blob therefore requires a master key plus one of: the user's password, their NTLM hash, a domain DPAPI backup key, or the machine context. Credential Manager, browser password stores, scheduled task credentials and certificate private keys all sit behind this layer, which is why DPAPI compromise is usually a consequence of another credential finding rather than an independent one.

- **CWE-522 (Insufficiently Protected Credentials):** The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`credential-dumping`](../credential-dumping/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the target is a user's own secrets and the user's password is unknown **THEN** the domain DPAPI backup key is the route; it requires domain administrator or the backup key itself
3. **IF** the target is machine-scoped secrets **THEN** SYSTEM context is sufficient, because the machine master key is derived from the machine account
4. **IF** browser credential stores are the objective **THEN** the encryption key is protected by DPAPI, so the same master-key problem applies
5. **IF** the target is Credential Manager entries **THEN** these are DPAPI blobs in the user profile and require the user's master key
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `credential-dumping-dpapi-and-secret-stores` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| LSASS memory rather than DPAPI blobs | [`credential-dumping-lsass-and-memory`](../credential-dumping-lsass-and-memory/SKILL.md) | Interactive secrets rather than stored blobs |
| Local or domain account hashes | [`credential-dumping-sam-and-ntds`](../credential-dumping-sam-and-ntds/SKILL.md) | Hive databases |
| A domain-wide decryption key | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | The DPAPI backup key as a durable asset |
| The recovered secret must be used | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | Credential reuse |
| Need the class-level branch table first | [`credential-dumping`](../credential-dumping/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the scope of the blob.** User scope, machine scope or domain backup scope. The scope decides whether a user password, SYSTEM context or the domain backup key is required, and it is readable from the blob's GUID structure without decrypting anything.
2. **Read the protection state of the master keys.** Master keys live in `%APPDATA%\Microsoft\Protect\<SID>` and `%WINDIR%\System32\Microsoft\Protect`. Their presence and ACL are readable without decryption and tell you whether any key material is reachable from the current context.
3. **Establish the decryption precondition you actually hold.** A user password or hash, a domain backup key, or SYSTEM. Reporting a DPAPI exposure without naming the precondition overstates the finding, because the blobs alone are not secrets.
4. **Baseline against a host with DPAPI-NG or credential roaming disabled.** A hardened host has few master keys, restricted ACLs, and no cached credentials for privileged accounts. Deviation is the finding, and the remediation is the roaming and caching policy.
5. **State the proof.** Proof is a decrypted blob whose plaintext matches a known value, plus the key material and context that permitted it. The presence of master key files alone is normal Windows behaviour and is not a finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `%APPDATA%\Microsoft\Protect\<SID>` master key files | Proves which user scopes have DPAPI keys and whether their ACL restricts them to that user; any Windows host. |
| Domain DPAPI backup key in `CN=BCKUPKEY` | Proves a domain-wide decryption capability exists and who can read it, which is the highest-value DPAPI asset; any AD. |
| Credential Manager entries with a target and a blob | Proves stored credentials exist, and the blob's protection decides whether they are recoverable; any Windows host. |
| Browser `Login Data` file with an encrypted `password_value` | Proves stored browser credentials protected by DPAPI, recoverable only with the user's key; Windows. |
| Scheduled task with a stored password | Proves a credential is stored with the task and protected by DPAPI or LSA secrets; any Windows host. |

## Worked Contrast

**Weak configuration — privileged accounts with credential roaming and cached credentials enabled:**

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Force | Select-Object Name
# multiple master keys for a privileged account, plus CachedLogonsCount 10,
# so every host the account touched holds recoverable material
```

**Hardened configuration — cached credentials disabled for privileged tiers and roaming restricted:**

```powershell
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
    -Name CachedLogonsCount -Value 0
# plus: block privileged accounts from interactive logon on lower-tier hosts
# verification: the value reads 0 and no master key exists for the account on that host
```

**Why this matters:** the recoverable material exists because the account logged on there, so the control is preventing the logon and the caching, and the verification is the absence of master keys on that host.

## When It Is NOT This Issue

- **Master key files present on a normal user profile.** Every Windows profile has them; their existence is not a finding, only their scope and ACL are.
- **A Credential Manager entry that cannot be decrypted without the user key.** The blob alone is not a credential exposure; state the precondition.
- **Protected browser stores on a host with no privileged logons.** A user's own browser credentials on their own workstation are a policy question, not a privilege boundary crossing.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `credential-dumping-dpapi-and-secret-stores` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `credential-dumping-dpapi-and-secret-stores` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: credential-dumping-dpapi-and-secret-stores
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-522 | Mapping: T1003]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) - Blue Detection/Defense Counterpart
- [`credential-dumping`](../credential-dumping/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`credential-dumping-lsass-and-memory`](../credential-dumping-lsass-and-memory/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`credential-dumping-sam-and-ntds`](../credential-dumping-sam-and-ntds/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `credential-dumping-dpapi-and-secret-stores` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-522, T1003`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/oxdf (12), CYBER_CPT/hacktricks (4), CYBER_CPT/github_security_md (2), ctf-solver-dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
