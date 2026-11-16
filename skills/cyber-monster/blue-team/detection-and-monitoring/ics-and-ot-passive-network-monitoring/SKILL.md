---
name: ics-and-ot-passive-network-monitoring
description: "Monitors OT/ICS Purdue Level 0-3 networks passively without active polling: Modbus/S7comm/DNP3/OPC-UA function-code allowlisting, unauthorized PLC firmware/ladder-logic download alerts, and rogue engineering-workstation MAC/IP pair detection. Use when building detection in SCADA or industrial environments."
family: detection-and-monitoring
tier: core
triggers: ["ot network monitoring", "ics anomaly detection", "modbus function code alert", "passive ot ids"]
cwe: [CWE-306]
owasp: []
attack: []
capec: []
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
corpus_sparse: true
---

# ICS and OT Passive Network Monitoring - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-ot-protocol-attacks`](../../../red-team/mobile-hardware-wireless-ics/ics-ot-protocol-attacks/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

OT protocols were designed for deterministic control traffic on isolated segments, so almost none of them carry authentication or integrity: a Modbus write is a function code and a register value, and any host on the segment that can reach port 502 can issue it. That single fact drives the whole detection model. Because there is no credential to observe, detection cannot ask *who* is authorised; it can only ask whether a conversation is one the process was designed to have. The workable unit is therefore a *learned communication matrix*: for each pair of endpoints and each protocol, the set of observed function codes, register ranges, request cadence, and byte volumes during a stable production period. Anything outside that matrix — a new source issuing a write function code, a programming or download service used from a host that never used it, a read of a register block no client has ever touched — is the signal. Two constraints shape the method. First, monitoring must be passive: active polling, even a benign scan, can stall a legacy device or a safety loop, and CISA's OT guidance is explicit that passive observation through a span port or tap is the safe default. Second, the baseline must span all operational modes — startup, steady state, batch changeover, maintenance — because a threshold learned in one mode will fire on every normal transition to another.

- **CWE-306 (Missing Authentication for Critical Function):** The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the sensor is inline or the collection requires active polling **THEN** stop: the deployment model itself is unsafe for OT. Monitoring must be passive through a span port or tap, and this is a precondition rather than a preference.
2. **IF** the protocol is Modbus/TCP **THEN** evaluate function codes, register addresses, and write direction against the communication matrix; **IF** the protocol is S7comm or DNP3 or EtherNet/IP **THEN** the equivalent discriminators are the service or function code plus the object or file identifier, and the matrix must be built per protocol because the code spaces do not map to each other.
3. **IF** the observed action is a read **THEN** it is lower priority than any write, program download, or mode change; **IF** the action is a write, a download, a cold/warm restart, or a mode change **THEN** treat it as a process-integrity event even when the source is an authorised workstation, because the question becomes whether the change was scheduled.
4. **IF** the source address is inside the learned matrix for that destination **THEN** compare the function code set; **IF** the source address is new to the destination **THEN** the finding is the new conversation itself, independent of the payload.
5. **IF** a maintenance window or change record covers the window **THEN** compare the observed actions against the work order's expected scope rather than against the steady-state matrix; **IF** no change record exists **THEN** any write is an unplanned change and escalates.
6. **IF** the passive sensor's span port misses a segment or a protocol is unparsed **THEN** report `Inconclusive (Visibility Gap)` for that segment, and never infer absence of activity there.
7. **IF** telemetry source covering `passive SPAN tap` or protocol parsing is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`ics-ot-protocol-attacks`](../../../red-team/mobile-hardware-wireless-ics/ics-ot-protocol-attacks/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Communication matrix build, function-code drift, write and download events |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Passive capture, Zeek OT parsers, matrix extraction |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The behaviour is on the IT side of the boundary rather than the OT segment | [`network-detection-and-ids`](../network-detection-and-ids/SKILL.md) | IT IDS semantics and east-west coverage |
| The rule must be authored for an OT protocol logsource | [`sigma-rule-authoring-cloud-and-network-rules`](../sigma-rule-authoring-cloud-and-network-rules/SKILL.md) | Network logsource categories and conversion |

## Procedure

1. **Fix sensor placement and prove it before analysing anything.** Identify the span ports and taps, the segments they cover, the protocols the parser understands, and the direction of each capture. A segment without a sensor is a permanent blind spot, and every finding must state which segments it can see.
2. **Build the communication matrix over a period that contains every operating mode.** Record, for each source-destination pair and protocol, the function or service codes observed, the register or object ranges touched, the request rate, and the byte volume. Note explicitly which modes the window included (startup, steady state, batch change, maintenance) because a matrix learned in one mode is a false-positive generator.
3. **Classify each protocol's discriminators before writing conditions.** Modbus: function code, register address and quantity, and read versus write direction. DNP3: function code plus object group and variation. S7comm: service code plus block or area identifier, with programming and download services treated as high severity. EtherNet/IP: service code plus object class. The code spaces are not comparable, so a rule written for one does not transfer.
4. **Rank by process impact rather than by novelty alone.** A new read on a diagnostic register is curiosity; a write to a holding register, a program download, a mode change, or a restart changes the process. Severity follows the effect on the physical process, not the rarity of the packet.
5. **Define the differential against the matrix and against the change record.** For a probe-window action, check first whether a work order covers it and its expected scope; then whether the pair's function-code set grew; then whether the source is new to the destination. These three tests are ordered by cost, and the first one resolves most of the volume.
6. **Join the IT side when the source is a workstation.** An engineering workstation that suddenly issues a download may be a legitimate change or a compromised host; the IT telemetry for that host (process events, authentication) is the discriminator, and the OT segment alone cannot supply it.
7. **Name the stop condition.** Stop and declare `Inconclusive` when a segment has no sensor, when the protocol is not parsed so its function codes are opaque, when the baseline window missed an operating mode, when the change record is unavailable for the window, or when the source host's IT telemetry is not collected.
8. **State what counts as proof.** Proof of an unauthorised process change is a write, download, mode change, or restart event on a destination whose communication matrix did not contain that action from that source, absent a covering work order, corroborated by either a subsequent process-value change or an IT-side action on the source host. A single new read is proof of nothing.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Source-destination pair with its observed function-code set and register ranges | communication matrix | The learned definition of normal for that pair, the baseline every later comparison needs |
| Write-direction function codes from a source that has only ever read from that destination | matrix drift | An unplanned change of role for a host, which is stronger evidence than a new host appearing |
| Programming, download, or block-transfer service codes per destination | program-change detection | Logic modification, the highest-impact OT event and the one with no authentication in most protocols |
| Cold or warm restart and mode-change events per destination | process-integrity | Whether the device was taken out of run mode, which often accompanies or follows a logic change |
| Distinct destination count per source host per protocol | role drift | A workstation contacting PLCs it has never contacted, which is a lateral-movement shape inside OT |
| New MAC and IP pairing on a segment where the pair is normally stable | rogue-device detection | Impersonation or an unauthorised engineering laptop, visible without any protocol depth |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
ALERT when any Modbus write function code is observed.
# No communication matrix, no source-destination pair, no change window.
# The HMI writes setpoints continuously and the batch controller rewrites
# the same registers every cycle, so the alert fires thousands of times an hour.
# Suppressing it removes the only signal that would catch an unauthorised write.
```

**High-Signal Grounded Artifact:**

```text
For each (src, dst, protocol) pair, learned over a 14-day window covering
startup, steady state, batch changeover and a maintenance period:
  fc_set        = observed function codes
  reg_ranges    = observed register/object ranges with direction
  req_rate_p95  = 95th percentile requests per minute

Probe-window finding when:
  action is write OR program-download OR mode-change OR restart
  AND action NOT IN learned fc_set for (src, dst)
  AND NOT covered by a work order whose scope lists (src, dst, action)
Report: src, dst, protocol, action, fc, register/object, work_order_id,
        subsequent process-value delta, IT-side process events for src.
```

**Why this matters:** the strong form learns what each pair actually does across all operating modes and then asks whether a high-impact action is new, so it separates a scheduled logic change from an unplanned one and does not fire on the setpoint writes the process performs continuously; the weak form alerts on a function code class, which in a live plant is the definition of normal traffic.

## When It Is NOT This Issue

- **Baseline learned in a single operating mode:** a matrix built only during steady-state production does not contain startup sequences, recipe changeovers, or maintenance downloads, so every transition looks like an intrusion. Confirm the modes the baseline covered before trusting a finding.
- **Scheduled engineering activity:** commissioning, patching, and logic updates are writes and downloads by design. The work order is the discriminator; without it the same event is indistinguishable from tampering, which is why the scope comparison comes before the matrix comparison.
- **Redundant or standby controllers synchronising:** a hot standby periodically receives a full program or state transfer from the primary, producing a download-shaped event on a fixed cadence. Treat it as part of the matrix once observed.
- **Span-port coverage limits:** a segment behind an unmanaged switch or across a routed boundary with no tap contributes nothing, so an untouched destination may simply be invisible. State the covered segments in every finding.
- **Protocol parser gaps:** an unparsed protocol yields connection records with no function codes, so its writes look like ordinary traffic. A gap in parsing is a visibility gap, not an absence of writes.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a segment or device is quiet when no passive sensor covers it or its protocol is unparsed.**
- **NEVER recommend active scanning, credential testing, or protocol fuzzing against an OT device, regardless of how useful the information would be.**
- **NEVER recommend containment that changes a control loop's state (isolating a PLC in run mode, blocking a safety-system segment) without the process engineer's explicit approval and a documented safe-state review.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** span ports and taps, covered segments, parsed protocols, and capture direction were recorded, and uncovered segments were listed as blind spots.
- [ ] **Differential defined:** the probe-window action was compared against the learned communication matrix for that pair, and against the work order's expected scope, before any severity was assigned.
- [ ] **Stop condition stated:** unmonitored segment, unparsed protocol, missing operating mode in the baseline, absent change record, or unavailable IT telemetry is named as the reason for `Inconclusive`.
- [ ] **Proof standard met:** high-impact action outside the matrix, no covering work order, and corroboration from either a process-value change or IT-side activity on the source host.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: ics-and-ot-passive-network-monitoring
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Span ports and covered segments, parsed protocols, baseline window and the operating modes it contained, UTC probe window, work orders consulted]
- **Behavioral Analysis**: [Action and function code, matrix membership for the pair, role drift, process-value effect; Taxonomy: CWE-306 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [IT-side process and authentication telemetry for the source host, MAC and IP pairing history, redundant-controller synchronisation check]
- **Containment / Detection / Hardening Action**: [Work-order or matrix update, sensor placement for the uncovered segment, rule to deploy with its protocol and severity mapping, process-engineer approval record]
```

## Related Sub-Skills

- [`ics-ot-protocol-attacks`](../../../red-team/mobile-hardware-wireless-ics/ics-ot-protocol-attacks/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Passive is a precondition, not a style choice:** any collection method that sends packets to an OT device is out of scope for this skill, because the monitoring action itself can change the process.
- **Taxonomy framing:** Keep framework references concise (parent CWE category `CWE-306`); OT techniques map to ATT&CK for ICS, whose detection guidance is expressed per technique rather than per data source.
- **Safety & authorization:** Analysis is read-only over passive captures; containment decisions belong to the process engineer, and this skill never proposes a state change to a control loop.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
