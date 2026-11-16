---
name: defense-evasion-and-log-tampering-indicator-removal
description: Indicator and artefact removal. Covers timestomping, file deletion, prefetch and shimcache artefact handling, and the residual evidence each leaves. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["timestomp", "indicator removal", "artefact cleanup", "prefetch delete"]
cwe: [CWE-693]
owasp: []
attack: [T1070]
capec: [CAPEC-93]
related: [defense-evasion-and-log-tampering, defense-evasion-and-log-tampering-log-and-audit-evasion, network-recon-and-port-scanning, service-enumeration]
parent: defense-evasion-and-log-tampering
---

# Defense Evasion and Log Tampering Indicator Removal - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Indicator removal is the deletion or alteration of artefacts that would otherwise corroborate an intrusion: prefetch files, event logs, shell history, scheduled task definitions, service registrations, dropped binaries, and the `UsnJrnl` records that describe their creation. Modern Windows keeps parallel records of the same action in NTFS metadata, the registry and the event log, so removing one leaves the others, and the removal itself becomes an artefact.

- **CWE-693 (Protection Mechanism Failure):** The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** files were deleted **THEN** `UsnJrnl` and `$MFT` records survive the deletion and show the name and timestamps
3. **IF** prefetch or shimcache entries were removed **THEN** their absence for a binary that ran is itself the signal, because those caches are written automatically
4. **IF** event logs were cleared **THEN** that is log tampering rather than indicator removal; see [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md)
5. **IF** scheduled tasks or services were removed **THEN** 4699 and 7040 record the deletion, which is the residual evidence
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `defense-evasion-and-log-tampering-indicator-removal` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Logs rather than files were altered | [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) | Channel integrity |
| Audit policy was disabled | [`defense-evasion-and-log-tampering-log-and-audit-evasion`](../defense-evasion-and-log-tampering-log-and-audit-evasion/SKILL.md) | Policy suppression |
| Telemetry pipeline was suppressed | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | ETW rather than files |
| The task or service is the persistence | [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) | Durable mechanisms |
| Need the class-level branch table first | [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish which artefacts should exist for the observed activity.** A process that executed produces a prefetch file, an `Amcache` entry, a `UserAssist` or `ShimCache` record depending on the build, and a `UsnJrnl` record. The expected set is the baseline, and a missing member is the finding.
2. **Read the residual records rather than the deleted ones.** `UsnJrnl` keeps the file name and the reason flags for a deletion, `$MFT` keeps the record entry, and the registry keeps the `Amcache` entry. These survive a file deletion and are read with forensic tooling.
3. **Compare artefact sets across similar hosts.** A host where a binary ran but no prefetch exists, while the same binary on peer hosts has one, is the strongest signal. Per-host comparison removes the false positives from builds that disable prefetch on SSDs.
4. **Name the stop condition and the evidence rule.** Stop at the first proven removal: a `UsnJrnl` delete record for a file whose creation record exists, or a missing cache entry for a binary with a confirmed execution event.
5. **State the proof.** Proof is the residual record that describes the removal plus the execution evidence it should have corroborated. A missing file is not proof of removal; a deletion record is.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `UsnJrnl` `FILE_DELETE` reason flag | Proves a named file was deleted, independent of whether it still exists; any NTFS volume. |
| Prefetch absent for a binary with a confirmed 4688 | Proves the prefetch cache was cleared or disabled, the classic anti-forensic action; Windows. |
| Windows Security 4699 for a scheduled task deleted | Proves a task was removed, which records the deletion even though the task is gone; Windows. |
| Service Control Manager 7040 for a service state change | Proves a service was reconfigured or removed, with the previous value; Windows. |
| `Amcache.hve` entry without a corresponding file | Proves execution history survived the binary's deletion, which is why `Amcache` is a reliable indicator; Windows. |

## Worked Contrast

**Weak configuration — prefetch disabled and audit of process creation off, so artefact removal leaves nothing to compare:**

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' `
    -Name EnablePrefetch
# EnablePrefetch 0 and no 4688 auditing: an attacker deleting a binary removes
# the only two records that would have described its execution
```

**Hardened configuration — prefetch enabled, process creation audited with command line, and Sysmon file events collected:**

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' `
    -Name EnablePrefetch -Value 3
auditpol /set /subcategory:'Process Creation' /success:enable
# command line inclusion: 'ProcessCreationIncludeCmdLine_Enabled' = 1
# verification: a launched binary produces both a prefetch file and a 4688 with its command line
```

**Why this matters:** indicator removal works by removing the only record, so the control is redundant recording and the verification is two independent artefacts for the same execution.

## When It Is NOT This Issue

- **Prefetch disabled by policy on an SSD-based fleet.** Some builds disable prefetch for performance; check the policy before reporting an absence as tampering.
- **A file absent because it was never created.** Confirm creation evidence before treating an absence as removal.
- **`UsnJrnl` truncation from normal journal rotation.** The journal wraps at its maximum size; check the volume's journal size and the record's timestamp against the wrap point.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `defense-evasion-and-log-tampering-indicator-removal` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `defense-evasion-and-log-tampering-indicator-removal` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: defense-evasion-and-log-tampering-indicator-removal
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: T1070]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`defense-evasion-and-log-tampering-log-and-audit-evasion`](../defense-evasion-and-log-tampering-log-and-audit-evasion/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `defense-evasion-and-log-tampering-indicator-removal` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693, T1070`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/atomic_red_team (8), CYBER_CPT/oxdf (4), CYBER_CPT/sigmahq (1), CYBER_CPT/mitre_attack_enterprise (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 8 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
