---
name: endpoint-detection-and-edr-operations
description: "Operates endpoint detection: understanding EDR telemetry, writing endpoint queries, triaging endpoint alerts and validating sensor coverage. Use when investigating host-level activity."
family: detection-and-monitoring
tier: core
triggers: ["edr operations", "endpoint detection", "edr query", "edr alert triage"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
---

# Endpoint Detection and EDR Operations - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`edr-evasion-and-amsi-bypass`](../../../red-team/network-ad-and-endpoint/edr-evasion-and-amsi-bypass/SKILL.md)

## Mechanism and Preconditions

An EDR agent is a user-mode service plus kernel callbacks, and everything it reports is a projection of that instrumentation rather than a recording of the operating system's own truth. A process tree assembled from `DeviceProcessEvents` reflects the parent the agent observed at creation time; Windows deliberately allows a child to name a different parent, and neither the agent nor the tree can show that mismatch after the fact. A file event reflects a minifilter callback, so a write that bypasses the filter stack or occurs before the agent loads is invisible. A network event reflects a specific API path, so traffic issued by a kernel driver or a socket opened through an unusual interface may not appear. On top of instrumentation sit two policy layers: the agent's own event-selection policy (what it chooses to record) and the tenant's ingestion policy (what it forwards and retains). The operational consequence is that "the EDR shows nothing" is a statement about the intersection of those layers, and the first question on any endpoint investigation is which layer could have dropped the event. Endpoint detection quality therefore depends on three habits: a per-host health and policy baseline, queries that use the fields the agent actually populates, and a discipline of correlating the EDR view against an independent source (a Windows event channel, Sysmon, or a memory capture) before concluding that a behaviour did not occur.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is "did this process run" **THEN** query process-creation events by device and time; **IF** the question is "what did this process do" **THEN** pivot on the process identifier and start time to network, file, and registry events, because a process tree alone carries no actions.
2. **IF** the host shows a healthy agent check-in and a current policy version **THEN** an empty result is a real negative for that policy; **IF** the check-in is stale or the policy predates the event **THEN** report `Inconclusive (Sensor Gap)` and state which layer is at fault.
3. **IF** the behaviour is parent-child lineage **THEN** treat the reported parent as an observation and corroborate with the process-creation event's own parent fields and start times; **IF** the reported parent looks impossible (a child older than its parent, or a session boundary crossing) **THEN** suspect reparenting rather than an agent error.
4. **IF** the behaviour is file or registry modification **THEN** check whether the agent's policy records that path or key, since most agents filter by path to control volume; **IF** the path is excluded by policy **THEN** the absence is by configuration and must be reported as such.
5. **IF** the behaviour is network **THEN** join the endpoint's network event to the flow record on device, destination, and a bounded window; **IF** only one plane shows the connection **THEN** the discrepancy is the finding and it localises the blind spot.
6. **IF** the same behavior appears in the EDR verdict stream but not in the raw event stream **THEN** the detection is coupled to the vendor model; record that and re-derive an analytic over raw events if the behaviour matters.
7. **IF** telemetry source covering `process tree` or `telemetry coverage` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`edr-evasion-and-amsi-bypass`](../../../red-team/network-ad-and-endpoint/edr-evasion-and-amsi-bypass/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Coverage baseline, process lineage, cross-plane join, policy audit |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Agent health, live triage collection, memory and event export |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The question is which observable could carry the behaviour at all | [`detection-engineering-behaviour-to-observable`](../detection-engineering-behaviour-to-observable/SKILL.md) | Sensor inventory and documented losses |
| The endpoint evidence must be corroborated from memory | [`memory-forensics-process-and-injection-analysis`](../../digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) | Process and injection artifacts from a capture |

## Procedure

1. **Establish the sensor baseline for this host before reading any event.** Record the agent version, policy version, last check-in, and the event categories the policy selects. An event category the policy does not record cannot be queried, and that is a configuration fact rather than an absence of activity.
2. **Anchor the investigation on an identifier and a start time.** Use the device plus process identifier plus creation timestamp, because process identifiers are reused and a bare identifier will return another process's events on a busy host.
3. **Read lineage from the creation event, not from the tree.** Take the reported parent, the parent's own creation time, the session identifier, and the integrity level. A parent created after its child, or a parent running in a different session, indicates reparenting or token manipulation rather than a display quirk.
4. **Corroborate the behaviour against a second plane.** For execution, compare the EDR process event with the Windows event channel or Sysmon; for files, compare with the file-system event or a directory listing; for network, compare with the flow record. Where the two disagree, the disagreement is the finding.
5. **Define the differential for triage.** Compare the host's behaviour against its own trailing baseline and against a peer group of similarly provisioned hosts: a management tool that runs everywhere is fleet behaviour, while the same process on one host only is a candidate.
6. **Name the stop condition.** Stop and declare `Inconclusive` when the agent's policy excludes the event category, when the check-in is stale across the window, when the identifier was reused so the timeline cannot be attributed, or when the ingestion layer retains less than the window under investigation.
7. **State what counts as proof.** Proof is a creation event with its full lineage and command line, a subsequent action event for the same identifier and start time, and agreement from a second independent plane on at least the existence and timing of the action. A single event from the EDR plane with no corroboration is a lead, and the output must say which corroboration is missing.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Agent version, policy version, and last check-in per device | coverage baseline | Whether the host's silence is meaningful; a stale agent or an older policy makes every later negative conditional |
| Process creation with parent image, parent creation time, session id, and integrity level | lineage | Whether the reported parent is the real one, which catches reparenting that a rendered tree hides |
| Action events joined on device, process id, and process creation time | timeline | What the identified process actually did, which a process tree can never show on its own |
| Same behaviour counted across the fleet versus on one host | peer differential | Whether the behaviour is administration or an outlier, the cheapest discriminator in endpoint triage |
| Endpoint network event matched to a flow record for the same destination and minute | cross-plane agreement | That the connection existed outside the agent's own view, closing the instrumentation-blind-spot question |
| Sysmon event 25 (process tampering) or 29 (executable write) rows for the device | independent channel | A second, differently instrumented view of image replacement or executable staging |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has "powershell"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
// No lineage, no parent, no sibling context, no fleet baseline.
// Every management script, every installer, every admin session.
// The analyst scrolls, finds nothing obviously wrong, and closes the alert.
```

**High-Signal Grounded Artifact:**

```kusto
let window = 1d;
DeviceProcessEvents
| where Timestamp > ago(window)
| where FileName =~ "powershell.exe"
| extend parent = tostring(InitiatingProcessFileName)
| where parent in~ ("winword.exe","excel.exe","outlook.exe","mshta.exe","wscript.exe")
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(window)
    | summarize peers = dcount(DeviceId) by FileName, InitiatingProcessFileName
  ) on FileName, InitiatingProcessFileName
| project Timestamp, DeviceName, AccountName, parent,
          ProcessCommandLine, initiating_time = InitiatingProcessCreationTime,
          peers
| where peers <= 3
| order by Timestamp desc
// Lineage gives the behaviour; the peer count separates a one-host anomaly
// from administration that runs everywhere. Both fields are required.
```

**Why this matters:** the strong form conditions on a lineage pair that is rare in a healthy estate and reports the fleet peer count beside the event, so the row carries both the behaviour and a reason to care; the weak form matches an executable name, which returns the entire management population and teaches the analyst to close endpoint alerts unread.

## When It Is NOT This Issue

- **Policy exclusion rather than absence:** most agents filter file and registry events by path to control volume, so a modification outside the selected paths is invisible by configuration. Read the policy before concluding the event did not occur.
- **Stale agent or downgraded policy:** a host that has not checked in since before the event, or that is running a policy older than the detection, produces a negative that says nothing about the host. Always report the check-in age next to the result.
- **Identifier reuse across the window:** process identifiers recycle, so a query on a bare identifier mixes two processes on a busy host. Anchor on the creation time as well, or the timeline will contain actions from an unrelated process.
- **Reparenting through a breakaway or a session change:** a child that names a different parent, or a process started under another session, appears with an impossible lineage in the tree. That is the technique, not an agent defect; corroborate with creation times.
- **Ingestion filtering or retention:** the tenant may ingest only a subset of what the agent records, and retention may be shorter than the window. A negative beyond the retention boundary describes the retention, not the host.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host is clean when the agent was stale, the policy excluded the category, or ingestion retention was shorter than the window.**
- **NEVER present a rendered process tree as proof of parentage without the creation events behind it.**
- **NEVER recommend destructive containment (isolating production clusters, wiping hosts, or disabling accounts) before preserving volatile evidence and confirming blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** agent version, policy version, check-in time, and selected event categories were recorded for every device in scope, and the retention window was confirmed.
- [ ] **Differential defined:** the host's behaviour was compared both against its own trailing baseline and against a peer group of similarly provisioned hosts.
- [ ] **Stop condition stated:** policy exclusion, stale check-in, identifier reuse, or short retention is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** creation event with lineage and command line, subsequent action event for the same identifier and start time, and agreement from a second independent plane.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: endpoint-detection-and-edr-operations
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Agent and policy version, check-in age, event categories selected, retention, UTC window, devices in scope]
- **Behavioral Analysis**: [Lineage with creation times, actions joined on identifier and start time, fleet peer count; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Second plane compared (Windows channel, Sysmon, or flow record), memory capture if volatile state matters, sibling hosts]
- **Containment / Detection / Hardening Action**: [Rule or policy change to deploy, isolation step sequenced after evidence capture, sensor or retention gap with owner]
```

## Related Sub-Skills

- [`edr-evasion-and-amsi-bypass`](../../../red-team/network-ad-and-endpoint/edr-evasion-and-amsi-bypass/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Policy is part of the answer:** an endpoint negative without the policy version and check-in age is not a negative. Report both beside every result.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); note that ATT&CK v19 restructured defense evasion into Stealth and Defense Impairment, so endpoint tampering analytics map differently than they did under v17.
- **Safety & authorization:** Triage queries and live collection are read-only; memory acquisition and isolation are approved actions with a chain-of-custody record, and production clusters are never isolated without application-owner sign-off.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 18 |
| Distinct dataset sources | 10 |
| Top sources | cyber-security/CyberSec-Dataset (5), cyber-security/vulnerability-intelligence__mitre-attack-techniques.json (2), CYBER_CPT/mitre_attack_enterprise (2), CYBER_CPT/sigmahq (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
