---
name: defense-evasion-and-log-tampering-log-and-audit-evasion
description: Log and audit trail evasion. Covers event log clearing, selective record deletion, audit policy changes and USN journal manipulation with detection implications. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["clear event log", "audit policy evasion", "usn journal", "log deletion"]
cwe: [CWE-693]
owasp: []
attack: [T1070]
capec: [CAPEC-93]
related: [defense-evasion-and-log-tampering, defense-evasion-and-log-tampering-indicator-removal, network-recon-and-port-scanning, service-enumeration]
parent: defense-evasion-and-log-tampering
---

# Defense Evasion and Log Tampering Log and Audit Evasion - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Audit policy is a set of subcategory switches, and disabling one stops the corresponding events at the source rather than deleting them afterwards. The change is recorded by 4719, but only if the audit policy change subcategory is itself enabled — which is the recursion that makes this technique work. The related surfaces are the audit policy registry values, the SACL on critical objects, and the event channel enablement, each of which can be weakened independently.

- **CWE-693 (Protection Mechanism Failure):** The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** a subcategory is off **THEN** `auditpol /get` shows the effective state; 4719 records when it changed, if that subcategory is enabled
3. **IF** an object SACL is missing **THEN** the object's audit entries are the control; without a SACL, object access generates nothing
4. **IF** a channel is disabled **THEN** `wevtutil gl` reports the enabled state; a disabled channel produces nothing regardless of policy
5. **IF** the log was cleared **THEN** that is removal rather than evasion; see [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `defense-evasion-and-log-tampering-log-and-audit-evasion` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Existing events were removed | [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) | Channel clearing and file editing |
| Artefacts were removed | [`defense-evasion-and-log-tampering-indicator-removal`](../defense-evasion-and-log-tampering-indicator-removal/SKILL.md) | Files and caches |
| The pipeline rather than the policy was suppressed | [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](../edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | ETW sessions |
| The configuration baseline is the deliverable | [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) | Detection coverage |
| Need the class-level branch table first | [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the effective audit policy, not the GPO.** `auditpol /get /category:*` shows what is applied on the host, which can differ from the domain policy when a local setting overrides it. The effective state is the only relevant one.
2. **Check the audit policy change subcategory first.** If `Audit Policy Change` is disabled, every subsequent weakening is unrecorded. That single subcategory is the highest-value check in this technique.
3. **Read object SACLs for the objects that matter.** Domain controller objects, the directory service object, sensitive files and the registry keys that control logging. Without a SACL, no amount of policy produces object-access events.
4. **Name the baseline and the stop condition.** A hardened baseline enables process creation with command line, logon, account management, policy change, object access on named objects, and PowerShell script block logging. Stop at the first subcategory whose absence removes a control the report depends on.
5. **State the proof.** Proof is the subcategory GUID with its effective state, or the missing SACL entry on a named object, or the disabled channel. The absence of events without one of those is not a finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Audit Policy Change` subcategory disabled | Proves subsequent audit weakening will be unrecorded, the recursion that enables the technique; Windows. |
| `Process Creation` without command line inclusion | Proves 4688 events exist but lack the command line, which removes the most useful field; Windows. |
| Missing SACL on the directory service object | Proves directory modification events are not generated regardless of policy; domain controllers. |
| `wevtutil gl` showing a channel disabled | Proves the channel produces nothing, independent of audit policy; Windows. |
| Local audit policy overriding domain policy | Proves the domain baseline is not in force on that host, which is how coverage quietly degrades; Windows. |

## Worked Contrast

**Weak configuration — audit policy change subcategory off and process creation without command line:**

```powershell
auditpol /get /subcategory:'Audit Policy Change'
# No Auditing, and ProcessCreationIncludeCmdLine_Enabled is 0:
# a further weakening of audit policy leaves no 4719, and 4688 has no command line
```

**Hardened configuration — policy change audited and command line included:**

```powershell
auditpol /set /subcategory:'Audit Policy Change' /success:enable /failure:enable
New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force
# verification: changing a subcategory now produces 4719, and a launched process produces 4688 with a command line
```

**Why this matters:** the technique relies on the recorder being switched off, so the controls are the policy-change subcategory and the command-line flag, verified by the events appearing.

## When It Is NOT This Issue

- **A subcategory off by design on a specialised server.** Some roles disable specific subcategories for volume reasons; check the documented baseline for that role.
- **A missing SACL on an object never meant to be audited.** Not every object needs a SACL; the finding requires an object whose access the control depends on.
- **A local policy that matches the domain policy.** Identical values are not an override; compare the settings rather than the presence of a local policy.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `defense-evasion-and-log-tampering-log-and-audit-evasion` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `defense-evasion-and-log-tampering-log-and-audit-evasion` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: defense-evasion-and-log-tampering-log-and-audit-evasion
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: T1070]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`defense-evasion-and-log-tampering`](../defense-evasion-and-log-tampering/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`defense-evasion-and-log-tampering-indicator-removal`](../defense-evasion-and-log-tampering-indicator-removal/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `defense-evasion-and-log-tampering-log-and-audit-evasion` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693, T1070`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/sigmahq (5), cyber-security/CyberSec-Dataset (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
