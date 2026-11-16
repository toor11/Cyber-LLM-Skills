---
name: automotive-and-can-bus
description: "Assesses automotive systems: CAN bus sniffing and injection, diagnostic protocol access, ECU identification and the limits of bench versus vehicle testing. Use when vehicle networks are in scope."
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["can bus", "automotive security", "ecu attack", "can injection"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-604]
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
---

# Automotive and CAN Bus - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

Automotive bus review is about the fact that conventional CAN has no authentication and no sender identity: a frame carries an 11- or 29-bit identifier, a data length, and up to eight bytes, and any node on the bus can transmit any identifier. Arbitration is by identifier priority, so a node that transmits a high-priority identifier frequently can starve others — which makes availability as much a concern as integrity. The mitigations are layered and each has a limit. AUTOSAR Secure Onboard Communication (SecOC) adds a message authentication code and a freshness counter to configured frames, so replay is rejected and forgery is detected — but only for the configured identifiers, and a compromised ECU that holds the key can still produce valid messages. Segmentation through a central gateway limits which identifiers cross which boundary, so a compromised infotainment head unit cannot reach a brake controller directly. Intrusion detection monitors message frequency, timing, and range against a learned baseline, which detects an injection that does not match the pattern. The 2025 regulatory context matters for what the review can require: UN R155 makes cybersecurity management and post-production monitoring an obligation in the markets that adopted it, and ISO/SAE 21434 clause 13 defines the monitoring and incident-response framework, so a bus without detection is a compliance gap as well as a technical one.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a safety-relevant identifier crosses a gateway from a non-safety domain **THEN** that is the finding; the gateway configuration is the citation.
2. **IF** a frame carrying a safety function has no SecOC MAC **THEN** the branch is forged-message exposure, and the identifier list is the scope.
3. **IF** the domain has no intrusion detection baseline **THEN** the finding is monitoring coverage, which is also the R155 obligation.
4. **IF** the question is the OTA update path rather than the bus **THEN** the branch is update verification, which belongs with Uptane-style metadata checks.
5. **IF** the concern is availability **THEN** the branch is identifier priority and bus load, which a timing analysis shows.
6. **IF** the review is authorised only for a bench setup **THEN** every probe is bench-only; never transmit on a live vehicle bus.
7. **IF** the concern is the vehicle's external attack surface rather than the internal bus **THEN** start at [`iot-device-exploitation`](../iot-device-exploitation/SKILL.md) for the connected-device surfaces.
8. **IF** every safety identifier is gateway-segmented, SecOC-protected, and covered by a detection baseline **THEN** record `Verified Safe` with all three.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the bus topology.** Which segments exist, which gateway connects them, and which identifiers cross. A bench capture with the gateway in place shows the crossing set.
2. **Classify each identifier by function.** Safety-relevant, comfort, diagnostic, and infotainment. The classification decides which controls are required.
3. **Choose the branch.** Gateway crossing, missing SecOC on a safety identifier, absent detection coverage, or priority-based availability exposure.
4. **Define the baseline-vs-probe differential.** Baseline: a capture of normal traffic, which establishes the identifier set, the cycle times, and the payload ranges. Probe: the same capture with a bench ECU transmitting an identifier outside its normal set. A frame accepted by a receiving ECU is the finding, and it must be demonstrated on a bench, never in a vehicle.
5. **Name the stop condition.** Stop at the first safety identifier whose frame is accepted without a MAC, or the first crossing that the gateway permits. Do not transmit on a live bus.
6. **State the proof.** Report the identifier, its function class, the gateway rule or the absence of a MAC, and the receiving ECU's behaviour. If every safety identifier is protected and segmented, record the negative with the identifier map.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A brake or steering identifier appearing on the infotainment segment | The gateway passes a safety identifier across a domain boundary, which is the segmentation finding | Gateway configuration, bench capture |
| A safety identifier frame with no MAC bytes | No SecOC protection, so any node can forge it | DBC definition, frame layout |
| A SecOC-protected identifier with a static freshness counter | Replay is possible despite the MAC, because the counter does not advance | Frame capture, counter field |
| An identifier transmitted at a cycle time outside its learned baseline | The detection signature of an injection, and the control's evidence | IDS log |
| A bus load above 80% with several high-priority identifiers | Availability exposure, because arbitration favours the highest priority | Bus load trace |
| A gateway rule permitting only the required identifiers per direction | The segmentation control, and the citation for a non-finding | Gateway configuration |

## Worked Contrast

**Vulnerable: safety identifier crossing the gateway, no SecOC, no detection baseline**

```text
# Gateway configuration: the infotainment segment can transmit a brake identifier.
# (Illustrative rule set; the finding is the crossing, not the syntax.)
segment infotainment -> segment chassis: allow 0x1A0, 0x2B0   # brake and steering
segment chassis -> segment infotainment: allow *

# And the frame layout for 0x1A0 has no MAC bytes:
BO_ 416 BRAKE_CMD: 8 ECU_CHASSIS
 SG_ BrakePressure : 0|16@1+ (0.1,0) [0|250] "bar"
 SG_ Counter       : 16|8@1+ (1,0) [0|255] ""
 # bytes 3-7 unassigned: no MAC
```

**Hardened: gateway admits only required identifiers, SecOC on safety frames, detection baseline**

```text
# The gateway admits the chassis segment's identifiers only in one direction and
# only those the receiving ECU needs.
segment infotainment -> segment chassis: deny *
segment chassis -> segment infotainment: allow 0x1A0, 0x2B0    # status only
```

```text
# The safety frame carries a MAC and a monotonic freshness counter:
BO_ 416 BRAKE_CMD_SECOC: 8 ECU_CHASSIS
 SG_ BrakePressure : 0|16@1+ (0.1,0) [0|250] "bar"
 SG_ Freshness     : 16|8@1+ (1,0) [0|255] ""
 SG_ Mac           : 24|32@1+ (1,0) [0|4294967295] ""
```

```text
# And the IDS baseline covers the identifier's cycle time and payload range:
ids rule: can_id=0x1A0 cycle_ms=20+-2 press_range=0..250 freshness_monotonic=true
```

**Why this matters:** The left configuration lets a compromised infotainment unit transmit a brake command that the chassis ECU accepts, because the identifier crosses the gateway and the frame has no authentication. The right configuration denies that direction, protects the frame with a MAC and a monotonic counter so a forgery or a replay is rejected, and adds a detection rule on the cycle time and payload range so an anomaly is visible even if a key-holding ECU is compromised.

## When It Is NOT This Issue

- **A diagnostic identifier reachable through the OBD port.** Physical access to the port is the precondition; the finding would be what the identifier can change.
- **A comfort identifier without SecOC.** Door and climate functions on a segmented bus are a lower class; state the classification.
- **A bench capture with the gateway removed.** The topology is not the deployed one; a finding needs the gateway in place.
- **A bus load spike during a diagnostic session.** Expected behaviour of the session, not an injection.
- **An identifier whose cycle time varies within the tolerance the IDS baseline defines.** The tolerance is the control.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `automotive-and-can-bus` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `automotive-and-can-bus` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: automotive-and-can-bus
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`firmware-extraction-and-emulation`](../firmware-extraction-and-emulation/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `automotive-and-can-bus` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/ctf_search (3), hackerone_disclosed_reports (1), CYBER_CPT/blackhills (1), CYBER_CPT/awesome_web_security (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
