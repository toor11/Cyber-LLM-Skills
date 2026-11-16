---
name: sigma-rule-authoring-windows-event-rules
description: Sigma rules for Windows event logs. Covers mapping Windows security, Sysmon and PowerShell events into Sigma log sources and fields. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: detection-and-monitoring
tier: leaf
triggers: ["sigma windows", "sysmon sigma", "event id sigma"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [sigma-rule-authoring, sigma-rule-authoring-cloud-and-network-rules, detection-engineering, yara-rule-authoring]
parent: sigma-rule-authoring
---

# Sigma Rule Authoring Windows Event Rules - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

Windows Sigma rules sit on three separate event models that do not share fields. The Security channel is audit-policy driven: an event ID exists only if the corresponding audit subcategory is enabled, and the field names come from the event's `EventData` template, which differs per event ID even within the same channel. Sysmon is configuration driven: the service emits only the event types its config enables, and schema versions add IDs — 4.90 covers 1 through 26 plus 29 `FileExecutableDetected`, while 27 and 28 are blocking-only entries for the driver and cannot be filtered on. PowerShell carries two channels with different content: 4104 records script block text only when script block logging is turned on, and 4103 records module pipeline execution only when module logging is on. Since Sysmon v15 the service runs as a protected process, so a rule that assumes an attacker can simply stop it is out of date, and the observable of interest moves to configuration and driver changes. A rule is correct only when it names the category, the event ID, and fields that exist in that event's own template.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `sigma-rule-authoring-windows-event-rules` **THEN** start at parent class [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) first.
2. **IF** the rule selects on a Security event ID **THEN** confirm the audit subcategory is enabled; **IF** it is not, the rule is `Inconclusive (Telemetry Gap)` and no field work will change that.
3. **IF** the rule selects on a Sysmon event ID **THEN** confirm the installed config includes that ID, and **IF** it is 27 or 28 **THEN** stop — those are blocking-only entries and never appear as filterable events.
4. **IF** the rule reads PowerShell script content **THEN** require 4104 with script block logging enabled; module logging gives 4103 with different fields and neither substitutes for the other.
5. **IF** a field is present in one event ID's template and not another **THEN** split the rule per event ID rather than writing one selection with a union field list.
6. **IF** telemetry source covering `Sysmon` or `EventID` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) | General class triage before variant specifics |
| Need event ID, config and field-template checks | [`QUERIES.md`](QUERIES.md) | Audit-policy, Sysmon-config and template classes |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | `Get-WinEvent`, `sysmon -c`, conversion |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Cloud or network event model instead | [`sigma-rule-authoring-cloud-and-network-rules`](../sigma-rule-authoring-cloud-and-network-rules/SKILL.md) | Operation names rather than event IDs |

## Procedure

1. **Confirm the channel, the event ID and the audit or config precondition together.** For Security, read the audit policy for the subcategory. For Sysmon, dump the running config and check the event type is in it. For PowerShell, confirm script block or module logging is enabled. All three are separate gates and each one alone makes the rule blind.
2. **Choose the branch: single-ID selection, multi-ID correlation, or config-change detection.** Single-ID rules are the majority. Multi-ID rules become correlation documents when ordering matters. Config-change rules target the registry and service surface that would disable the previous two, which is what remains observable once Sysmon runs as a protected process.
3. **Define the baseline-versus-probe differential per host and per parent image.** Convert the rule and count hits per `Computer` split by `ParentImage` over a quiet 7-day window and a positive replay. Windows estates have heavy management tooling; the per-parent split is what separates administration from intrusion.
4. **Name the stop condition.** Stop when the audit subcategory is disabled, when the Sysmon config omits the event type, when the event ID is blocking-only, when the field exists in the channel but not in that event's template, or when the tenant forwards only a filtered subset of the channel.
5. **State what counts as proof.** Proof is the converted rule firing on a captured event of that exact ID from that exact channel, with the audit or config precondition read from the host, plus a quiet-window count for the same parent image. Firing in a lab with full auditing enabled proves the logic, not the coverage.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Audit policy state for the subcategory behind the event ID | audit precondition | Whether the event can exist at all; a disabled subcategory makes the rule permanently silent |
| Running Sysmon config listing the event types | config precondition | Which Sysmon IDs the host actually emits, and whether 27/28 were mistakenly assumed filterable |
| `EventData` template for one event ID | field template | The exact field names that ID carries, which differ from a neighbouring ID in the same channel |
| PowerShell 4104 presence for a host running scripts | script telemetry | That script block logging is on; without it, content-based rules have no input |
| Hits per `Computer` split by `ParentImage` | baseline differential | Whether the rule's noise is management tooling rather than malicious lineage |
| Registry and service events touching Sysmon's own configuration | config tamper | Attempts to reduce visibility, which is the durable observable now that the service is protected |
| `CommandLine` containing an encoded blob with a decoding parent | lineage | Execution shape rather than a string match, which an installer script does not reproduce |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```yaml
# WEAK: an event ID with no channel, no category, and a field that may not exist.
title: Suspicious Service Install
logsource:
  product: windows
detection:
  sel:
    EventID:
      - 7045
      - 4697
    ImagePath|contains: 'temp'
  condition: sel
# 7045 is System and 4697 is Security; they do not share an ImagePath field.
# No category, so the pipeline cannot map a source, and no audit precondition stated.
```

**High-Signal Grounded Artifact:**

```yaml
title: Service Installed From User-Writable Directory
id: 2f8b1c47-9a3e-4d51-b6c0-7e1a5d2f8b94
status: experimental
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ImagePath|contains:
      - '\Users\'
      - '\ProgramData\'
      - '\Temp\'
      - '\AppData\'
  filter_signed_installers:
    ServiceType: 'user mode service'
    StartType: 'auto start'
  condition: selection and not filter_signed_installers
falsepositives:
  - Vendor updaters that stage an installer under ProgramData before promoting it to a service
level: medium
tags:
  - attack.persistence
  - attack.t1543.003
```

**Why this matters:** the weak rule merges two channels under one selection and keys on a field only one of them carries, with no category for the pipeline to map. The strong rule names one service channel and one event ID, selects on a path property that ID actually carries, and implements its exclusion as a real condition so the documented false positive is a control rather than a note.

## When It Is NOT This Issue

- **Disabled audit subcategory:** event IDs 4688, 4689 and 4656 in particular require explicit subcategory enablement. The rule is correct and there is nothing to match.
- **Sysmon config omitting the event type:** a config tuned for process creation only emits nothing for network or registry events, so a rule on ID 3 or 13 is silent on that fleet.
- **Blocking-only Sysmon entries:** 27 and 28 exist to block file and registry access and are not emitted as filterable events; a rule selecting them can never fire.
- **PowerShell logging mode mismatch:** 4104 needs script block logging and 4103 needs module logging. A rule written for one and deployed where only the other is enabled returns nothing.
- **Filtered forwarding:** many estates forward a subset of channels to the SIEM. The event exists on the host and is absent from the index, which reads identically to an absence of activity.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER invent event IDs, channel names or `EventData` field names** — read them from a captured event in that channel.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `Sysmon` or `EventID` was disabled, rotated out, or uncollected.**
- **NEVER assume Sysmon can be stopped by a normal process action** — since v15 it runs as a protected process, so the observable is configuration and driver change, not process termination.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** channel, event ID and the audit or Sysmon config precondition were each read from the host, not assumed.
- [ ] **Branch chosen:** single-ID, multi-ID correlation or config-change detection was selected, with blocking-only IDs excluded.
- [ ] **Differential defined:** converted-rule hits compared per host split by parent image between a quiet window and a positive replay.
- [ ] **Stop condition stated:** disabled subcategory, omitted config event type, blocking-only ID, missing template field or filtered forwarding was named.
- [ ] **Proof standard met:** the rule fires on a captured event of that exact ID and channel, with the precondition output recorded beside it.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: sigma-rule-authoring-windows-event-rules
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`sigma-rule-authoring-cloud-and-network-rules`](../sigma-rule-authoring-cloud-and-network-rules/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Three gates, not one:** audit policy, Sysmon config and PowerShell logging each independently silence a correct rule. Record which gate you cleared.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; `Get-WinEvent` and `sysmon -c` read state, they do not change it.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 19 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/awesome_list (6), CYBER_CPT/ctf_search (4), SecEval/windows_security (3), CYBER_CPT/blackhills (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 10 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
