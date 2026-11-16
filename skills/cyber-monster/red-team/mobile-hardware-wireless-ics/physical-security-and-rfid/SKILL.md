---
name: physical-security-and-rfid
description: "Assesses physical access controls: RFID and NFC cloning, lock bypass, badge cloning and physical entry techniques. Use when physical penetration is authorised."
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["rfid cloning", "physical access", "badge clone", "lock bypass"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-604]
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
---

# Physical Security and Rfid - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

Physical security review establishes what a person with brief physical access can achieve, and the credential technologies decide most of it. A 125 kHz proximity card carries a static identifier that any reader-model clone reproduces, so a captured identifier is a permanent credential. A 13.56 MHz MIFARE Classic uses Crypto1, whose keystream and nested-authentication weaknesses allow key recovery from a few captured authentications, and a MIFARE DESFire or an iCLASS SE with diversified keys is the current design because each card's key is derived from a master and the card's UID. On the reader side the failure is almost always the controller's decision logic: it authenticates the card, not the person, so a cloned card is a valid credential, and the compensating control is a second factor — a PIN, a biometric, or a rule that requires two credentials for a sensitive zone. The rest of physical review is the enclosure and the interfaces: an exposed USB or Ethernet port inside a kiosk, an unmonitored door contact, a tailgating gap in a mantrap, and a service panel held by a commodity lock. Each is a finding with a specific access path, and none of them requires breaking a cryptographic primitive.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the credential is a 125 kHz proximity card **THEN** the identifier is clonable by design, and the finding is the absence of a second factor for that zone.
2. **IF** the credential is MIFARE Classic **THEN** the branch is key recovery, and the control is a migration to a diversified-key card.
3. **IF** the credential is a DESFire or an SE card with diversified keys **THEN** the card is a control, and the branch moves to the controller's decision logic.
4. **IF** a sensitive zone has one-factor card access **THEN** that is the finding regardless of the card technology.
5. **IF** the finding is an exposed port or a service panel **THEN** the branch is the enclosure, not the credential.
6. **IF** the question is the network side of a badge system **THEN** start at [`iot-device-exploitation`](../iot-device-exploitation/SKILL.md) for the controller's own services.
7. **IF** every card is diversified-key, every sensitive zone requires two factors, and every enclosure is tamper-evident **THEN** record `Verified Safe` with all three.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the credential technology.** Frequency, card family, and whether the identifier is static or the card performs a cryptographic exchange. The technology determines which findings are possible.
2. **Read the controller's decision.** Card only, card plus PIN, card plus biometric, or a rule that varies by zone and time. This is where almost every physical finding lives.
3. **Choose the branch.** Static-identifier credential, recoverable card key, single-factor sensitive zone, or enclosure exposure.
4. **Define the baseline-vs-probe differential.** Baseline: a legitimate credential presented at the reader, which grants the expected access. Probe: a second card or a cloned identifier presented in a lab, with the controller's log as the evidence. Access granted on the probe is the finding.
5. **Name the stop condition.** Stop at the first zone where one factor grants access to a sensitive area, or the first enclosure opening that exposes a usable port. Do not enter a restricted area beyond the authorised scope.
6. **State the proof.** Report the credential technology, the controller rule, the zone, and the observed grant. If every sensitive zone requires two factors, record the negative with the access matrix.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A 125 kHz reader and a card with a printed 10-digit number | A static identifier credential, clonable with a reader-model writer | Proximity card system |
| A MIFARE Classic 1K card with default keys on a sector | Recoverable keys, so the card's data is readable and writable | 13.56 MHz card |
| A DESFire EV2/EV3 card with diversified keys | Per-card key derivation, which is the current control | Card and controller |
| A sensitive zone whose reader accepts a card alone | Single-factor access to a restricted area, which is the finding | Controller configuration |
| A tamper-evident seal on a service panel, intact at audit | The enclosure control, and a non-finding | Physical inspection |
| An exposed USB port inside a publicly accessible kiosk | A physical interface reachable without opening the enclosure | Kiosk hardware |

## Worked Contrast

**Vulnerable: static-identifier card, single-factor access to a sensitive zone**

```text
# Reader: 125 kHz proximity. Card: static 40-bit identifier, printed on the back.
[reader] 125 kHz ASK, id=0x1A2B3C4D5E
[controller] zone=server-room, rule=any valid card, schedule=24x7

# Access matrix: one factor, no PIN, no second credential, no escort rule.
```

**Hardened: diversified-key card with a card-plus-PIN rule on sensitive zones**

```text
# Reader: 13.56 MHz, DESFire EV3 with diversified keys derived from the master and
# the card UID.
[reader] 13.56 MHz ISO14443-4, card=DESFire EV3, auth=mutual, keys=diversified
[controller] zone=server-room, rule=card+PIN, schedule=07:00-19:00, escort_required=false
[controller] zone=lobby, rule=card, schedule=24x7
```

**Why this matters:** The left system grants a restricted area on a credential anyone can copy with a handheld reader and a blank card, so the physical control is equivalent to a printed code. The right system derives a unique key per card so a clone cannot authenticate, and requires a PIN in addition to the card for the sensitive zone, so possession alone is not sufficient.

## When It Is NOT This Issue

- **A 125 kHz card granting access only to a low-sensitivity area with camera coverage.** The classification is the control; state it.
- **A MIFARE Classic card used only as a cafeteria payment token with a small balance.** The exposure is bounded; report the balance limit.
- **A single-factor reader on a zone whose door is also staffed.** A person is the second factor.
- **A service panel with a commodity lock inside a locked room.** The layered access is the control.
- **A cloned card in a test that the controller rejected.** That is the control working.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `physical-security-and-rfid` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `physical-security-and-rfid` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: physical-security-and-rfid
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `physical-security-and-rfid` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 30 |
| Distinct dataset sources | 13 |
| Top sources | OffsecCyber (9), ctf-solver-dataset (5), cyber-security/vulnerability-intelligence__nvd-realtime-cves-2.json (2), cyber-security/vulnerability-intelligence__nvd-realtime-cves-7.json (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
