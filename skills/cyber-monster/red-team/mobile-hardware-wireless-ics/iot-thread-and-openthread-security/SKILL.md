---
name: iot-thread-and-openthread-security
description: "Assesses IEEE 802.15.4 Thread and OpenThread mesh networks: MeshCoP DTLS commissioning (PSKd entropy), Network Key rotation, Border Router IPv6 routing boundaries, MLE advertisement spoofing resistance, and replay counter handling. Use when auditing smart-home, building-automation, or Thread mesh firmware."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["openthread security", "thread mesh protocol", "meshcop commissioning", "border router thread", "pskd thread"]
cwe: [CWE-287, CWE-327]
owasp: []
attack: []
capec: []
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
corpus_sparse: true
---

# IOT Thread and Openthread Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Thread is an IPv6 mesh over IEEE 802.15.4 and its security model has three layers that fail independently. The network layer: a network-wide key protects MAC frames, derived from the network master key, and every device in the mesh holds it — so compromise of any device reveals the key and defeats the layer for the whole network. The commissioning layer: a joiner authenticates to a joiner router using a PSKd derived from a device passcode, and the DTLS session carries the network credentials; the security of this step is exactly the entropy of the passcode, and a fleet-wide static PSKd makes every device's commissioning equivalent. The application layer: Thread itself provides no application security, so Matter's CASE, or an application protocol's own encryption, is what actually protects payloads. Thread 1.4 adds two mechanisms that change this review: Thread Credentials Sharing, which uses a temporary DTLS channel and one-time administrative passcodes (ePSKc) to share credentials between border routers without exposing the long-lived secret, and Thread Commissioning over Authenticated TLS (TCAT), a certificate-based commissioning method over BLE for commercial deployment. Both are optional, so the review question is whether they are enabled and whether the fallback path still accepts a shared credential.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the same PSKd or passcode is provisioned across a device fleet **THEN** that is the finding; one device's passcode compromises every join.
2. **IF** the border router has no ephemeral-key (ePSKc) support and cross-ecosystem sharing is a requirement **THEN** the branch is credential sharing, and the long-lived network key is the exposure.
3. **IF** the finding is Matter's commissioning or fabric model **THEN** switch to [`matter-protocol-commissioning-and-fabric-security`](../matter-protocol-commissioning-and-fabric-security/SKILL.md); Thread carries Matter's transport.
4. **IF** the finding is the 802.15.4 frame layer itself **THEN** start at [`ieee-802-15-4-and-zigbee-mesh-security`](../ieee-802-15-4-and-zigbee-mesh-security/SKILL.md).
5. **IF** the review is about the application payload **THEN** Thread is not the control; name the application-layer protocol that is.
6. **IF** every device has a unique passcode, the joiner window is bounded, and TCAT or ePSKc is used for commercial sharing **THEN** record `Verified Safe` with all three facts.
7. **IF** the joiner window is unbounded or the border agent accepts joins indefinitely **THEN** the finding is the window, measured in the time an attacker has to brute-force a passcode.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish the layer under review.** Network key handling, commissioning, or application payload. Each has a different evidence source and a different remedy, and mixing them produces a report about Thread rather than about the device.
2. **Read the commissioning configuration.** The PSKd provisioning method: per-device random, derived from a printed passcode, or a constant in firmware. The joiner window duration and whether it closes after the first join.
3. **Choose the branch.** Fleet-static PSKd, unbounded joiner window, network key shared with a device class, or a fallback path that bypasses TCAT or ePSKc.
4. **Define the baseline-vs-probe differential.** Baseline: one device commissioning with its own passcode. Probe: a second commissioning attempt using the first device's passcode, or a join attempt after the window should have closed. Success on the probe is the finding, and it needs a lab network.
5. **Name the stop condition.** Stop at the first successful join using credentials that belong to another device, or the first join accepted outside the window. Do not attempt to brute-force a passcode.
6. **State the proof.** Report the provisioning method, the window, the credential's uniqueness across the fleet, and the join result. If every device has a unique credential and the window closes, record the negative with the configuration.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A PSKd constant in firmware shared by a device model | Every device commissions with the same secret, so one extracted firmware compromises the fleet | Firmware, manufacturing data |
| A printed passcode with 27 bits of entropy and no attempt limit | The commissioning space is brute-forceable if the joiner window is long | Device label, joiner implementation |
| `OPENTHREAD_CONFIG_BORDER_AGENT_EPHEMERAL_KEY_ENABLE` | ePSKc support, which is the Thread 1.4 mechanism for sharing without exposing the long-lived key | OpenThread build configuration |
| `OPENTHREAD_CONFIG_BLE_TCAT_ENABLE` | Certificate-based commissioning, which is the commercial path and is optional | OpenThread build configuration |
| A joiner window left open after commissioning | The attack window is unbounded, so passcode entropy is the only control | Border agent configuration |
| A unique passcode per device with a bounded window | The control: one device's compromise does not extend to another | Manufacturing and commissioning |

## Worked Contrast

**Vulnerable: fleet-static PSKd, unbounded joiner window, no ephemeral key**

```c
/* The PSKd is compiled in, so every unit of this model commissions with the same
   secret, and the joiner window never closes. */
static const char *kPskd = "THREAD1234";
otJoinerStart(instance, kPskd, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
```

```text
# Border agent state: the steering data stays valid indefinitely.
> commissioner state
petition
> joiner port any
done
```

**Hardened: per-device derived PSKd, bounded window, ephemeral key for sharing**

```c
/* The PSKd is derived from a per-device secret provisioned at manufacture, and the
   joiner stops accepting once the device has joined. */
otJoinerStart(instance, device_pskd, NULL, VENDOR_OUI, VENDOR_MODEL,
              NULL, NULL, NULL, NULL);
/* After a successful join: */
otJoinerStop(instance);
/* And the border agent exposes an ephemeral key only for the sharing window: */
#if OPENTHREAD_CONFIG_BORDER_AGENT_EPHEMERAL_KEY_ENABLE
otBorderAgentSetEphemeralKey(instance, epsk, epsk_len, timeout_seconds);
#endif
```

**Why this matters:** The left device gives every unit the same commissioning secret and never closes the window, so extracting one firmware lets an attacker join any network of that model, and the network-wide key follows. The right device derives a unique PSKd per unit, stops the joiner once commissioned, and uses the Thread 1.4 ephemeral key so credential sharing has a bounded window without exposing the long-lived key.

## When It Is NOT This Issue

- **A printed passcode on the device label that is unique per unit and rate-limited.** That is the intended commissioning model.
- **A network-wide key shared across devices.** It is the Thread design; the compensating control is the application-layer encryption.
- **TCAT not enabled on a consumer product.** TCAT is optional and aimed at commercial deployment.
- **A joiner window that is open during a manufacturing window by design.** State the window's duration and the physical-access precondition.
- **A Thread network with a single vendor's devices.** The ecosystem-sharing risk is out of scope.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `iot-thread-and-openthread-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `iot-thread-and-openthread-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: iot-thread-and-openthread-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287, CWE-327 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `iot-thread-and-openthread-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
