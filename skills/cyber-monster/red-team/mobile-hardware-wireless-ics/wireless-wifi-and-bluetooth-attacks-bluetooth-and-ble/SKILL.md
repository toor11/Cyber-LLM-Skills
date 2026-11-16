---
name: wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble
description: Bluetooth and BLE attacks. Covers BLE enumeration, pairing weaknesses, replay of unauth characteristics and Bluetooth classic attack surface. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["ble attack", "bluetooth sniffing", "ble replay"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-604]
related: [wireless-wifi-and-bluetooth-attacks, wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid, wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin, android-app-security]
parent: wireless-wifi-and-bluetooth-attacks
---

# Wireless Wifi and Bluetooth Attacks Bluetooth and Ble - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

Bluetooth and BLE security is decided at pairing and at the attribute layer, and the two are independent. At pairing: BR/EDR legacy pairing derives the link key from a short PIN or a fixed one, so a captured exchange is crackable; LE Legacy pairing has the same weakness through the temporary key; LE Secure Connections uses ECDH and is not crackable from a capture, but only when the association model supplies authentication — Numeric Comparison or Passkey Entry — because Just Works uses the ECDH exchange with no authentication at all, which leaves the connection open to an active man-in-the-middle. At the attribute layer: a GATT server exposes characteristics with properties (`read`, `write`, `write-without-response`, `notify`) and permissions, and a peripheral that permits an unauthenticated write to a control characteristic is the same finding as an unauthenticated API endpoint. The 2025 research on the Wi-Fi Easy Connect and on BLE implementations converges on the same point: the protocol primitives are sound, and the association model plus the authorisation check on each characteristic decide the exposure. The precondition is radio proximity, and the proof is a pairing-mode observation plus a characteristic read or write from a central the device should not trust.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a device pairs with Just Works **THEN** there is no authentication, so an active man-in-the-middle is possible; that is the finding for a device carrying data.
2. **IF** a device uses BR/EDR legacy pairing or LE Legacy pairing **THEN** the link key is derivable from a capture, which is the branch.
3. **IF** a GATT characteristic permits an unauthenticated write **THEN** the branch is the attribute permission, independent of the pairing mode.
4. **IF** the device uses LE Secure Connections with Passkey or Numeric Comparison **THEN** pairing is authenticated, and the remaining question is the characteristic permissions.
5. **IF** the question is Wi-Fi rather than Bluetooth **THEN** start at [`wireless-wifi-and-bluetooth-attacks`](../wireless-wifi-and-bluetooth-attacks/SKILL.md).
6. **IF** the device is an audio peripheral with no data channel beyond media streaming **THEN** record the pairing mode as a hardening note rather than a finding.
7. **IF** every pairing is authenticated and every sensitive characteristic requires an encrypted and authenticated link **THEN** record `Verified Safe` with both facts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`wireless-wifi-and-bluetooth-attacks`](../wireless-wifi-and-bluetooth-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Observe the pairing exchange.** `btmon` or a sniffer capture shows the pairing method in the clear: Just Works, Passkey Entry, Numeric Comparison, or OOB. That is the evidence for the pairing half.
2. **Enumerate the GATT table.** Services and characteristics with their properties and permissions, read from a central. The table is the attribute half.
3. **Choose the branch.** Unauthenticated pairing, legacy pairing, unauthenticated characteristic write, or an encrypted-link requirement absent on a control characteristic.
4. **Define the baseline-vs-probe differential.** Baseline: a read of a benign characteristic from a paired central, which succeeds. Probe: a write to a control characteristic from an unpaired or Just-Works central. Acceptance is the finding.
5. **Name the stop condition.** Stop at the first characteristic that accepts a write from a central the device should not trust. Do not actuate a physical function.
6. **State the proof.** Report the pairing method from the capture, the characteristic UUID and its properties, and the write result. If every sensitive characteristic requires authentication, record the negative with the table.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `Pairing method: Just Works` in the snoop log | No authentication in pairing, so an active MITM is possible | `btmon`, snoop capture |
| `Pairing method: Passkey Entry (LE Secure Connections)` | Authenticated pairing with ECDH, which is the control | `btmon`, snoop capture |
| A characteristic with `write-without-response` and no encryption requirement | An unauthenticated write path to whatever the characteristic controls | GATT table |
| A control characteristic whose permission is `read/write` with no `encrypt/authenticate` flag | The same exposure at the attribute layer | GATT permissions |
| BR/EDR legacy pairing in a capture | A weak link key derivation, crackable offline | BR/EDR capture |
| A characteristic requiring an authenticated link for writes | The control, and the citation for a non-finding | GATT permissions |

## Worked Contrast

**Vulnerable: Just Works pairing and an unauthenticated control characteristic**

```text
# Pairing with no authentication, and a characteristic that accepts a write from
# any central.
$ btmon -w pair.log &
$ bluetoothctl pair AA:BB:CC:DD:EE:FF
  > HCI Event: LE Meta Event (0x3e) plen 12
      LE Connection Complete
  > SMP Pairing Request
      AuthReq: 0x00 (Bonding: No, MITM: No, Secure Connections: No)
  > SMP Pairing Response
      AuthReq: 0x00
      Pairing method: Just Works
```

```text
# GATT table: the actuator characteristic accepts an unauthenticated write.
$ gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0012 -n 01
Characteristic value was written successfully
```

**Hardened: LE Secure Connections with a passkey, and an authenticated write requirement**

```text
$ btmon -w pair.log &
$ bluetoothctl pair AA:BB:CC:DD:EE:FF
  > SMP Pairing Request
      AuthReq: 0x0d (Bonding: Yes, MITM: Yes, Secure Connections: Yes)
      Pairing method: Passkey Entry (LE Secure Connections)
[agent] Passkey: 481920
```

```text
# The actuator characteristic requires an authenticated, encrypted link:
$ gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0012 -n 01
Error: Characteristic Write Request failed: Authentication Requirements
```

**Why this matters:** The left device pairs with no authentication, so an attacker within range can pair and write to the actuator characteristic, which is a physical action taken by a stranger. The right device requires a passkey over LE Secure Connections, and the characteristic refuses a write on a link that has not been authenticated, so both the pairing and the attribute layer are closed.

## When It Is NOT This Issue

- **Just Works pairing on a device that only reads a sensor value with no actuation.** No authority to exercise.
- **A characteristic that is readable without authentication but carries a public value such as a firmware version.** Read-only and non-sensitive.
- **BR/EDR legacy pairing on a device that requires a physical button press to pair and has no data channel.** The physical precondition is the control.
- **A GATT table with many characteristics, all requiring authentication for write.** Correctly configured.
- **A snoop log from a pairing that used OOB data.** OOB is authentication by another channel.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-327 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`wireless-wifi-and-bluetooth-attacks`](../wireless-wifi-and-bluetooth-attacks/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](../wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](../wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/hacktricks (5), CYBER_CPT/infocon (2), CYBER_CPT/blackhills (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
