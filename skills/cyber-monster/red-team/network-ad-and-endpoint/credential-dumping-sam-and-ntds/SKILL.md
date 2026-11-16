---
name: credential-dumping-sam-and-ntds
description: SAM, SECURITY and NTDS.dit extraction. Covers registry hive extraction, volume shadow copy access to NTDS.dit, and offline domain hash extraction. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["ntds.dit", "sam hive dump", "secretsdump", "shadow copy ntds"]
cwe: [CWE-522]
owasp: []
attack: [T1003]
capec: [CAPEC-60]
related: [credential-dumping, credential-dumping-lsass-and-memory, credential-dumping-dpapi-and-secret-stores, network-recon-and-port-scanning]
parent: credential-dumping
---

# Credential Dumping Sam and Ntds - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md)

## Mechanism and Preconditions

The SAM and SECURITY hives hold local account hashes and cached domain verifiers, and NTDS.dit holds every domain account hash. The hives are protected by file ACLs plus the boot key stored in the SYSTEM hive, so reading them requires either SYSTEM-level file access or an offline parse with the SYSTEM hive alongside. NTDS.dit is different in kind: on a live domain controller it is locked, so extraction happens either from a volume shadow copy or through directory replication, and the latter only requires the replication extended right rather than local administrator.

- **CWE-522 (Insufficiently Protected Credentials):** The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`credential-dumping`](../credential-dumping/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the target is a member server or workstation **THEN** SAM and SECURITY hives plus the SYSTEM hive are the artefacts; `SeBackupPrivilege` or SYSTEM is the precondition
3. **IF** the target is a domain controller **THEN** NTDS.dit via a shadow copy or replication; the replication right is the real finding
4. **IF** cached domain credentials are the question **THEN** the `SECURITY` hive holds them only if `CachedLogonsCount` is above zero
5. **IF** the objective is only local accounts **THEN** SAM is sufficient; NTDS.dit adds nothing for local accounts
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `credential-dumping-sam-and-ntds` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| LSASS memory rather than hives | [`credential-dumping-lsass-and-memory`](../credential-dumping-lsass-and-memory/SKILL.md) | Process access instead of file access |
| DPAPI secrets rather than hashes | [`credential-dumping-dpapi-and-secret-stores`](../credential-dumping-dpapi-and-secret-stores/SKILL.md) | Per-user protected blobs |
| The replication right is the edge | [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) | Who holds the replication ACE |
| The hashes need recovering | [`password-cracking-and-wordlists`](../password-cracking-and-wordlists/SKILL.md) | Offline recovery |
| Need the class-level branch table first | [`credential-dumping`](../credential-dumping/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Determine which database answers the question.** SAM for local accounts, SECURITY for cached verifiers and LSA secrets, NTDS.dit for domain accounts. Each has a different access precondition, and a report that conflates them misstates the privilege required.
2. **Read the file ACLs and the backup privilege before extracting.** `icacls` on the hive files plus the current token's privileges. Hive files are locked while the system runs, so a direct read usually fails even with a permissive ACL — the shadow copy or `reg save` path is the one that works.
3. **Establish the replication branch for a domain controller.** `Replicating Directory Changes` and `Replicating Directory Changes All` on the domain naming context are the rights that permit a DCSync-style extraction. Read who holds them; that holder set is the finding, because it is far broader than Domain Admins in many estates.
4. **Baseline against a hardened domain controller.** Replication rights held only by domain controllers and sanctioned backup or monitoring accounts, with SACL auditing on the directory service object. Deviation is an escalation path independent of local administrator access.
5. **State the proof.** Proof is the exported hive or the replication response, plus the ACL or ACE that permitted it. For NTDS via replication, the proof is the `DS-Replication-Get-Changes-All` ACE and a successful replication call, not the resulting hash file.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `DS-Replication-Get-Changes-All` ACE holders | Proves who can extract every domain hash without local administrator rights; any AD. |
| `CachedLogonsCount` value | Proves whether the SECURITY hive contains usable cached verifiers; any Windows host, default 10. |
| SAM hive ACL without SYSTEM-only restriction | Proves a non-SYSTEM principal can read local hashes; any Windows host. |
| Volume shadow copy of `C:\` | Proves NTDS.dit is reachable as a file despite the live lock; domain controllers. |
| `SeBackupPrivilege` enabled for a service account | Proves hive files can be read regardless of their ACL, which is a file-DACL bypass; any Windows host. |

## Worked Contrast

**Weak configuration — a monitoring service account holds replication rights on the domain naming context:**

```powershell
$dn = (Get-ADDomain).DistinguishedName
(Get-Acl "AD:$dn").Access |
  Where-Object { $_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') }
# a non-DC service account holds Get-Changes-All, so it can replicate every hash
```

**Hardened configuration — replication rights restricted to domain controllers and sanctioned backup accounts:**

```powershell
$dn = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:$dn"
$acl.Access | Where-Object {
    $_.ObjectType -eq [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -and
    $_.IdentityReference -notmatch 'Domain Controllers|Backup'
} | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
Set-Acl -Path "AD:$dn" -AclObject $acl
# verification: the ACE read shows only DC and backup trustees
```

**Why this matters:** domain-wide hash extraction needs a replication right rather than local administrator, so the control is that ACE and the verification is re-reading the naming-context descriptor.

## When It Is NOT This Issue

- **A shadow copy that exists for backup purposes.** VSS snapshots are normal; the finding is who can create or mount one without administrative rights.
- **Hive files with permissive ACLs but an active lock.** The ACL alone does not make them readable while the system runs; state the access path that actually works.
- **Replication rights held by a documented backup product.** Backup software legitimately replicates; verify the account against the tool inventory before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `credential-dumping-sam-and-ntds` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `credential-dumping-sam-and-ntds` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: credential-dumping-sam-and-ntds
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
- [`credential-dumping-dpapi-and-secret-stores`](../credential-dumping-dpapi-and-secret-stores/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `credential-dumping-sam-and-ntds` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-522, T1003`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/github_security_md (10), CYBER_CPT/oxdf (9), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
