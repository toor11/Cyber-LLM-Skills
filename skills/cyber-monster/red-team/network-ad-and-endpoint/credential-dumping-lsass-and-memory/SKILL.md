---
name: credential-dumping-lsass-and-memory
description: LSASS and process memory credential extraction. Covers dumping LSASS with native tools, comsvcs and procdump, and handling PPL protection and detection. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["lsass dump", "comsvcs minidump", "procdump lsass", "ppl lsass"]
cwe: [CWE-522]
owasp: []
attack: [T1003]
capec: [CAPEC-60]
related: [credential-dumping, credential-dumping-sam-and-ntds, credential-dumping-dpapi-and-secret-stores, network-recon-and-port-scanning]
parent: credential-dumping
---

# Credential Dumping Lsass and Memory - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md)

## Mechanism and Preconditions

LSASS holds credential material for every interactive and network logon: NTLM hashes, Kerberos tickets and, where WDigest is enabled, plaintext passwords. Reading it requires a handle with read access, which in turn requires `SeDebugPrivilege` or a kernel-mode primitive. Two protections change the answer completely: RunAsPPL makes LSASS a protected process so user-mode handles are refused, and Credential Guard moves the material into a VBS enclave so even a successful dump contains nothing usable.

- **CWE-522 (Insufficiently Protected Credentials):** The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`credential-dumping`](../credential-dumping/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** RunAsPPL is enabled **THEN** user-mode handle requests fail with access denied; the remaining route is a kernel primitive, which is a different and much higher-risk finding
3. **IF** Credential Guard is running **THEN** a dump yields no usable secrets; report the protection, not a credential exposure
4. **IF** a dump file already exists **THEN** the finding is the artefact and its location, plus whether the protection state allowed it
5. **IF** the objective is tickets rather than hashes **THEN** a ticket cache may be simpler; see [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `credential-dumping-lsass-and-memory` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The target is the SAM or NTDS database | [`credential-dumping-sam-and-ntds`](../credential-dumping-sam-and-ntds/SKILL.md) | Hive files and replication |
| The target is per-user DPAPI secrets | [`credential-dumping-dpapi-and-secret-stores`](../credential-dumping-dpapi-and-secret-stores/SKILL.md) | Master keys and credential blobs |
| The protection must be bypassed in kernel mode | [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | BYOVD and PPL |
| The recovered material must be used | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | Hash and ticket reuse |
| Need the class-level branch table first | [`credential-dumping`](../credential-dumping/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the protection state before touching the process.** `RunAsPPL`, the VBS status and Credential Guard. These three values predict whether a dump is possible and whether it will contain anything, so a dump taken without them cannot be interpreted.
2. **Establish the handle access the technique needs.** A read dump needs `PROCESS_VM_READ` with `PROCESS_QUERY_INFORMATION` (0x1010 or 0x1410); a full dump needs much more. The access mask is the detection signal and the proof that the request was dump-shaped rather than diagnostic.
3. **Baseline against the same host with protections on.** On a host with PPL and Credential Guard, the identical attempt returns access denied and the resulting artefact has no secrets. That is the reference that turns a tool result into a finding.
4. **Set the stop condition and the artefact rule.** Stop once the artefact proves readability, and record its path, size and hash. Credential material stays in the agreed evidence store; it is not copied to a workstation for convenience.
5. **State the proof.** Proof is a dump whose content contains a logon session that the assessor can independently tie to the host, plus the protection state that permitted it. The tool's banner is not proof.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `GrantedAccess` 0x1010 on LSASS | Proves a read-oriented handle, the access mask of a credential dump; Windows with Sysmon event 10. |
| `RunAsPPL` value 1 | Proves LSASS is a protected process, so user-mode access is refused and only a kernel primitive remains; Windows 8.1 and later. |
| Credential Guard in `SecurityServicesRunning` | Proves secrets are in a VBS enclave, so a successful dump contains no usable material; Windows 10 Enterprise and Server 2016 and later. |
| `.dmp` file with an LSASS-consistent size | Proves the artefact exists regardless of which tool produced it, which is the durable evidence after cleanup; Windows. |
| `WDigest\UseLogonCredential` value 1 | Proves plaintext passwords are cached in memory, which raises the impact of any dump; Windows 8.1 and later where the value was re-enabled. |

## Worked Contrast

**Weak configuration — LSASS unprotected and WDigest caching re-enabled:**

```powershell
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
    /v UseLogonCredential /t REG_DWORD /d 1 /f
# RunAsPPL not set: a user-mode dump returns plaintext passwords for every
# interactive session, not just hashes
```

**Hardened configuration — PPL enabled and WDigest plaintext caching disabled:**

```powershell
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
    /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RunAsPPL /t REG_DWORD /d 1 /f
# reboot required; verification: the dump attempt is denied and UseLogonCredential reads 0
```

**Why this matters:** the two controls are independent: PPL blocks the handle and WDigest decides whether plaintext exists in memory, so both must be verified separately.

## When It Is NOT This Issue

- **A dump created but containing no secrets.** With Credential Guard running this is the expected result and proves the control, not a failed technique.
- **An access-denied handle request.** PPL refusing the handle is the control working; reporting it as a technique failure misdescribes the host.
- **Security-product access to LSASS.** EDR and antivirus open LSASS handles continuously with the same masks; exclude the sanctioned product binaries before alerting on the access mask alone.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `credential-dumping-lsass-and-memory` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `credential-dumping-lsass-and-memory` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: credential-dumping-lsass-and-memory
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-522 | Mapping: T1003]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) - Blue Detection/Defense Counterpart
- [`credential-dumping`](../credential-dumping/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`credential-dumping-sam-and-ntds`](../credential-dumping-sam-and-ntds/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`credential-dumping-dpapi-and-secret-stores`](../credential-dumping-dpapi-and-secret-stores/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `credential-dumping-lsass-and-memory` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-522, T1003`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/sigmahq (4), CYBER_CPT/oxdf (1), CYBER_CPT/lolbas (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
