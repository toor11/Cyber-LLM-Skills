---
name: credential-dumping
description: "Extracts credentials from a compromised host or domain: LSASS and SAM dumps, DPAPI secrets, cached credentials, browser stores, and NTDS.dit extraction. Use after achieving local or domain admin on a Windows system."
family: network-ad-and-endpoint
tier: core
triggers: ["credential dumping", "lsass dump", "mimikatz", "sam dump", "ntds.dit", "dpapi"]
cwe: [CWE-522]
owasp: []
attack: [T1003]
capec: [CAPEC-60]
related: [credential-dumping-lsass-and-memory, credential-dumping-sam-and-ntds, credential-dumping-dpapi-and-secret-stores, network-recon-and-port-scanning]
---

# Credential Dumping - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md)

## Mechanism and Preconditions

Credential dumping is the extraction of authentication material from a live system: LSASS memory holds interactive logon secrets and Kerberos tickets, the SAM database holds local account hashes, NTDS.dit holds every domain hash, and DPAPI protects per-user blobs with keys derived from the user's password. Each source has its own protection: RunAsPPL and Credential Guard for LSASS, boot-key and DPAPI protector escrow for the registry hives, and the domain controller's own replication rights for NTDS.dit. The finding is which protection was absent, not which tool was used.

- **CWE-522 (Insufficiently Protected Credentials):** The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is LSASS memory **THEN** check RunAsPPL and Credential Guard first; with Credential Guard on, a dump yields no usable material regardless of access
2. **IF** the target is local account hashes **THEN** use [`credential-dumping-sam-and-ntds`](../credential-dumping-sam-and-ntds/SKILL.md) for SAM, SECURITY and NTDS.dit
3. **IF** the target is per-user secrets **THEN** use [`credential-dumping-dpapi-and-secret-stores`](../credential-dumping-dpapi-and-secret-stores/SKILL.md) for DPAPI and credential stores
4. **IF** only tickets are of interest **THEN** tickets are in LSASS but also reusable from a cache; see [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md)
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `credential-dumping` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Local account and domain database hashes | [`credential-dumping-sam-and-ntds`](../credential-dumping-sam-and-ntds/SKILL.md) | SAM, SECURITY, NTDS.dit and DCSync |
| Per-user secrets and credential stores | [`credential-dumping-dpapi-and-secret-stores`](../credential-dumping-dpapi-and-secret-stores/SKILL.md) | DPAPI masters, Credential Manager, browser stores |
| The process memory that holds secrets | [`credential-dumping-lsass-and-memory`](../credential-dumping-lsass-and-memory/SKILL.md) | LSASS access and dump artefacts |
| The hashes need recovering or reusing | [`password-cracking-and-wordlists`](../password-cracking-and-wordlists/SKILL.md) | Offline recovery and reuse |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify which credential store is in scope and what protects it.** LSASS with RunAsPPL versus without, SAM with a boot key versus with DPAPI-NG, and NTDS.dit reachable by file or only by replication. The protection decides whether the technique is a file read, a process access, or a directory replication — three very different findings.
2. **Establish the privilege the technique needs.** LSASS access needs `SeDebugPrivilege` or an equivalent, SAM and SECURITY hives need `SeBackupPrivilege` or SYSTEM, and NTDS.dit needs Domain Controller rights or replication rights. Naming the required privilege makes the finding about the privilege gap rather than the tool.
3. **Baseline the protection state before dumping anything.** `RunAsPPL`, VBS and Credential Guard status, and the hive file ACLs. A dump taken without recording these produces a result that cannot be interpreted: an empty LSASS dump with Credential Guard on is the control working, not a failed technique.
4. **Set the stop condition and the handling rule.** Stop at the first artefact that proves the store is readable. Credential material is sensitive evidence: name the file, its location and its retention, and do not move it beyond the agreed evidence store.
5. **State the proof.** Proof is the artefact plus the protection state: a dump file whose content includes a known logon session, or a hive export whose hashes match an account whose password is known. The tool's success message is not proof.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `RunAsPPL` value in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | Proves whether LSASS runs as a protected process, which decides whether user-mode access is possible at all; Windows 8.1 and later. |
| `SecurityServicesRunning` containing Credential Guard | Proves credential material is in a VBS enclave, so LSASS dumps yield no usable secrets; Windows 10 Enterprise and Server 2016 and later. |
| Sysmon event 10 with `GrantedAccess` 0x1010 or 0x1410 on LSASS | Proves a read-oriented handle request, the characteristic access mask of a dump; Windows with Sysmon. |
| SAM and SECURITY hive file ACLs | Proves whether a non-SYSTEM principal can read the hives directly, which skips LSASS entirely; any Windows host. |
| NTDS.dit file ACL on a domain controller | Proves whether the database is readable as a file rather than only via replication; domain controllers. |

## Worked Contrast

**Weak configuration — LSASS unprotected, no Credential Guard, and debug privilege available to service accounts:**

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL
# RunAsPPL absent, Credential Guard not running, and SeDebugPrivilege granted to
# a service account: a single dump yields every interactive logon secret
```

**Hardened configuration — PPL enabled, Credential Guard running, and debug privilege restricted:**

```powershell
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RunAsPPL /t REG_DWORD /d 1 /f
# enable VBS and Credential Guard via GPO, then reboot
# remove SeDebugPrivilege from service accounts in local policy
# verification: a dump attempt returns access denied and the dump contains no secrets
```

**Why this matters:** the exposure is the absence of process protection, so the controls are PPL and Credential Guard, and the verification is an access denial plus a dump with no usable material.

## When It Is NOT This Issue

- **Credential Guard enabled with a successful-looking dump.** The dump may succeed and contain no secrets, because the material is in a VBS enclave; a large dump file is not evidence of credential exposure.
- **An empty or truncated LSASS dump.** Protected processes can cause a dump to be created but unreadable; verify content against a known logon session before reporting.
- **Cached domain credentials under a disabled policy.** `CachedLogonsCount` of 0 means no cached verifier exists to recover; check the policy before reporting cached-credential exposure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `credential-dumping` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `credential-dumping` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: credential-dumping
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-522 | Mapping: T1003]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) - Blue Detection/Defense Counterpart
- [`credential-dumping-lsass-and-memory`](../credential-dumping-lsass-and-memory/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`credential-dumping-sam-and-ntds`](../credential-dumping-sam-and-ntds/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`credential-dumping-dpapi-and-secret-stores`](../credential-dumping-dpapi-and-secret-stores/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `credential-dumping` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-522, T1003`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 33 |
| Distinct dataset sources | 11 |
| Top sources | CYBER_CPT/atomic_red_team (9), CYBER_CPT/oxdf (5), cyber-security/CyberSec-Dataset (4), SecEval/attck (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
