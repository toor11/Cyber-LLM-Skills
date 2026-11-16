---
name: ieee-802-15-4-and-zigbee-mesh-security
description: "Assesses IEEE 802.15.4 and Zigbee networks: well-known Trust Center Link Key (`ZigBeeAlliance09`) fallback during join, unencrypted NWK key transport, install-code provisioning, and frame replay checks. Use when reviewing Zigbee or 802.15.4 sensor deployments."
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["zigbee security", "802.15.4 mesh", "trust center link key", "zigbee install code"]
cwe: [CWE-321, CWE-327]
owasp: []
attack: []
capec: []
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
corpus_sparse: true
---

# Ieee 802 15 4 and Zigbee Mesh Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Zigbee security has one well-known historical weakness and a set of current ones. The historical weakness is the global Trust Center link key `ZigBeeAlliance09`, a default shipped in pre-3.0 devices to ease interoperability: any device that knows it can join a network and receive the network key, so a device still using it is compromised by a public constant. Zigbee 3.0 replaces it with install codes — a per-device secret, usually printed on the label, from which a unique link key is derived — and requires the Trust Center link key to be updated after joining. Three current problems remain. The install-code path is only as strong as the code's entropy and the vendor's handling of it, and a code that is a device-model constant is the fleet-static case. Legacy coexistence: a 3.0 device joining a network formed by a legacy parent still uses the global key, so the upgrade does not help until the whole mesh is upgraded. Touchlink commissioning, used for lighting, has documented eavesdropping, replay, and takeover weaknesses, so a device that accepts Touchlink joins is reachable without the network key. The 2025 research literature confirms all three and adds that Zigbee 3.0 remains exposed to network-rejoin and denial-of-service patterns.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a device joins with `ZigBeeAlliance09` or a vendor default link key **THEN** that is the finding; the key is public and the network follows.
2. **IF** install codes are used but the code is a model constant **THEN** the branch is fleet-static, which is equivalent to the default key with extra steps.
3. **IF** the device accepts Touchlink commissioning **THEN** the branch is proximity commissioning, which bypasses the network key entirely.
4. **IF** the mesh mixes 3.0 and legacy devices **THEN** the branch is coexistence: the weakest device sets the network's key model.
5. **IF** the finding is the Thread mesh rather than Zigbee **THEN** start at [`iot-thread-and-openthread-security`](../iot-thread-and-openthread-security/SKILL.md).
6. **IF** the finding is the 802.15.4 frame layer or RF capture **THEN** start at [`rf-and-sdr-attacks`](../rf-and-sdr-attacks/SKILL.md).
7. **IF** every device uses a unique install code, the Trust Center link key update is enforced, and Touchlink is disabled **THEN** record `Verified Safe` with all three.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish the key model.** Global default key, vendor default, install code, or install code plus link-key update. Each is a different finding class and only the last is the current design.
2. **Check for Touchlink.** A device that accepts Touchlink joins has a commissioning path that does not involve the Trust Center.
3. **Check the join path.** Whether the Trust Center sends the network key encrypted with the global key, and whether legacy parents are still present.
4. **Define the baseline-vs-probe differential.** Baseline: a join with a valid unique install code, which succeeds. Probe: a join attempt with the global default key, or a Touchlink join from proximity. Success on the probe is the finding, and a network capture of the join frames is the evidence.
5. **Name the stop condition.** Stop at the first join accepted with a key or path that should not be valid. Do not attempt a network-wide key recovery.
6. **State the proof.** Report the key model, the joining device, the frames captured, and the result. If every join uses a unique install code with an enforced link-key update, record the negative with the capture.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `ZigBeeAlliance09` in firmware or a join capture | The global default Trust Center link key, which is public knowledge | Firmware strings, 802.15.4 capture |
| An install code that is identical across units of a model | Fleet-static commissioning, equivalent to a default key | Device label, manufacturing data |
| A Touchlink join accepted from a nearby device | A commissioning path that bypasses the Trust Center and the network key | Touchlink cluster implementation |
| A Trust Center link key that is never updated after joining | The global or vendor key stays in use for the device's life | Join sequence capture |
| A legacy parent in a mesh with 3.0 devices | The network still distributes keys under the old model | Network topology |
| An install-code join with a per-device code and a link-key update | The current correct design, and the control to cite | Join sequence capture |

## Worked Contrast

**Vulnerable: global default link key, no link-key update, Touchlink enabled**

```text
# Firmware strings show the well-known default key in use:
$ strings firmware.bin | rg -i "ZigBeeAlliance09|SuperSecret"
ZigBeeAlliance09

# Capture of a join: the network key is transported encrypted with that default key.
IEEE 802.15.4: Transport Key, Key Type: Network Key (0x01)
  Encrypted with: Trust Center Link Key (global default)

# And the device accepts a Touchlink join with no Trust Center involvement:
> zll commission
Touchlink commissioning started
```

**Hardened: per-device install code, enforced link-key update, Touchlink disabled**

```text
# The install code is unique per unit and provisioned at manufacture:
$ strings -a -n 12 firmware.bin | rg -i "install|code" | head -2
(no embedded install code; read from the manufacturing area at first boot)

# Capture of a join: a unique link key derived from the install code, then an update.
IEEE 802.15.4: Transport Key, Key Type: Trust Center Link Key (0x04)
  Derived from: install code (device unique)
IEEE 802.15.4: Transport Key, Key Type: Network Key (0x01)
  Encrypted with: updated Trust Center Link Key

# Touchlink disabled in the build:
$ rg -n "ZLL|TOUCHLINK" firmware.map | head -2
(no ZLL commissioning symbols present)
```

**Why this matters:** The left device joins with a key printed in every Zigbee security guide, so the network key is derivable from a capture, and Touchlink gives a second path that needs only proximity. The right device derives a unique link key from a per-unit install code, updates that key before the network key is sent, and has the Touchlink commissioning code removed from the build.

## When It Is NOT This Issue

- **A network-wide key.** It is the Zigbee design; the finding would be the link-key model that delivered it.
- **A legacy device on a network where the Trust Center enforces link-key updates for 3.0 devices.** The legacy device is a documented exception; state the topology.
- **An install code printed on a label with a physical-access precondition.** That is the intended model.
- **A vendor-specific key that is unique per device but stored in a secure element.** The key custody is the argument.
- **Touchlink present in the firmware but not reachable from the commissioning flow.** The presence is not the exposure; the accepted join is.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ieee-802-15-4-and-zigbee-mesh-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ieee-802-15-4-and-zigbee-mesh-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ieee-802-15-4-and-zigbee-mesh-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-321, CWE-327 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ieee-802-15-4-and-zigbee-mesh-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-321, CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/mitre_attack_enterprise (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
