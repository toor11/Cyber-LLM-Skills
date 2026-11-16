---
name: wireless-wifi-and-bluetooth-attacks
description: "Attacks wireless networks: WPA and WPA2 handshake capture and cracking, WPS abuse, evil twin and rogue AP, plus Bluetooth and BLE pairing and sniffing attacks. Use when wireless is in scope."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["wifi attack", "wpa cracking", "evil twin", "bluetooth attack", "ble sniffing", "wps"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-604]
related: [wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid, wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin, wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble, android-app-security]
---

# Wireless Wifi and Bluetooth Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

Wi-Fi and Bluetooth review is about which pairing and association handshake the deployment actually uses, because each has a different set of known weaknesses and a different control. On the Wi-Fi side: WPA2-PSK derives the same pairwise master key from one passphrase for every client, so a captured four-way handshake yields an offline-crackable material, and WPA3-SAE replaces that with a PAKE whose Dragonblood weaknesses were timing and cache side channels in hash-to-curve implementations rather than a protocol break; WPA2-Enterprise shifts authentication to a RADIUS server and moves the risk to client certificate validation and to the evil-twin problem, where a client that does not validate the server certificate will happily complete a handshake with an attacker's AP. On the Bluetooth side: BR/EDR legacy pairing derives the link key from a weak exchange and is crackable from a capture, LE Legacy pairing has the same weakness, and LE Secure Connections with numeric comparison or passkey is the current design; a BLE device in Just Works mode has no authentication at all. The family defects that cut across both are downgrade (a WPA3 transition mode that still accepts WPA2, a Bluetooth device that falls back to legacy pairing) and the management-frame weaknesses that allow deauthentication and disassociation. The precondition is radio proximity and, for offline attacks, a capture.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the network is WPA2-PSK **THEN** the finding is the shared passphrase model, and the control is a long random passphrase plus rotation, not the cipher.
2. **IF** the network is WPA3-SAE with transition mode enabled **THEN** the branch is downgrade: a client that accepts WPA2 gives an attacker the WPA2 handshake.
3. **IF** the network is WPA2-Enterprise **THEN** the branch is server-certificate validation on the client, which is where evil-twin succeeds.
4. **IF** the capture shows a four-way handshake for a PSK network **THEN** the branch is offline cracking exposure; switch to [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](../wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid/SKILL.md).
5. **IF** the finding is a rogue AP or an evil twin **THEN** switch to [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](../wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin/SKILL.md).
6. **IF** the finding is a BLE or BR/EDR pairing mode **THEN** switch to [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](../wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble/SKILL.md).
7. **IF** every network uses WPA3-SAE without transition mode or WPA2-Enterprise with certificate validation, and every Bluetooth device uses LE Secure Connections **THEN** record `Verified Safe` with the negotiated parameters.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid` | [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](../wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin` | [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](../wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble` | [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](../wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the radios and their negotiated parameters.** SSIDs with their AKM suites, clients with their pairing modes, and whether transition or fallback modes are accepted. The negotiated result is the evidence, not the configuration file.
2. **Read the authentication model.** PSK, SAE, or Enterprise for Wi-Fi; Just Works, passkey, numeric comparison, or OOB for Bluetooth. Each has a specific weakness set.
3. **Choose the branch.** Shared-passphrase model, transition-mode downgrade, missing server-certificate validation, or legacy pairing.
4. **Define the baseline-vs-probe differential.** Baseline: an association with the intended parameters, which the client accepts. Probe: an association offering the weaker parameter, or an AP presenting a certificate the client should reject. Acceptance on the probe is the finding.
5. **Name the stop condition.** Stop at the first accepted weaker association, or the first capture that yields an offline-crackable handshake. Do not attempt to crack a production passphrase.
6. **State the proof.** Report the SSID or device, the negotiated AKM or pairing mode, the accepted weaker parameter, and the control. If every association uses the strongest available parameter, record the negative with the beacon and association frames.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A beacon advertising both `PSK` and `SAE` AKM suites | Transition mode, so a client that accepts PSK gives an attacker a WPA2 handshake | Beacon and probe response frames |
| `RSN AKM: PSK` with a passphrase from a wordlist | The shared-passphrase model, and the offline attack's feasibility | Four-way handshake capture |
| `RSN AKM: 802.1X` with no server certificate validation on the client | Evil-twin success: the client completes a handshake with any AP claiming the SSID | Client supplicant configuration |
| A BLE device pairing with `Just Works` | No authentication, so any central can pair | BLE pairing exchange |
| BR/EDR legacy pairing from a capture | A weak link key derivation, crackable offline | Bluetooth capture |
| `SAE` only, with `PMF` required and no PSK AKM | The strongest Wi-Fi configuration and the control to cite | Beacon frames |

## Worked Contrast

**Vulnerable: transition-mode WPA3, shared passphrase, and a BLE peripheral in Just Works**

```text
# The AP advertises both PSK and SAE, so a client that accepts PSK produces a
# WPA2 four-way handshake that is offline-crackable.
Beacon (SSID=corp-wifi):
  RSN AKM: PSK, SAE
  RSN Cipher: CCMP
  MFP: not required

# And the paired peripheral uses Just Works:
$ bluetoothctl
[NEW] Device AA:BB:CC:DD:EE:FF SensorTag
[CHG] Device AA:BB:CC:DD:EE:FF Paired: yes
  Pairing method: Just Works
```

**Hardened: SAE-only with PMF required, and LE Secure Connections with a passkey**

```text
# SAE only, management-frame protection required, so there is no WPA2 handshake to
# capture and no deauthentication path.
Beacon (SSID=corp-wifi):
  RSN AKM: SAE
  RSN Cipher: CCMP-128
  MFP: required
  Transition Disable: 1

# And the peripheral uses LE Secure Connections with a passkey entry:
$ bluetoothctl
[CHG] Device AA:BB:CC:DD:EE:FF Paired: yes
  Pairing method: Passkey Entry (LE Secure Connections)
```

**Why this matters:** The left network lets an attacker capture a WPA2 four-way handshake by associating as a PSK client and then crack it offline at leisure, and the Just Works peripheral accepts any central that connects. The right network offers only SAE with management-frame protection required and transition disabled, so there is no PSK handshake and no deauthentication lever, and the peripheral requires a passkey over LE Secure Connections so pairing needs an out-of-band secret.

## When It Is NOT This Issue

- **WPA2-PSK with a long random passphrase, rotated, on a network with no sensitive traffic.** The model is unchanged but the exposure is bounded; report the passphrase management.
- **WPA3 transition mode during a documented migration.** The window is the finding's scope; state the migration date.
- **A BLE device in Just Works mode that carries no sensitive data.** No authentication and nothing to protect.
- **A WPA2-Enterprise network where the client validates the certificate against a pinned CA.** The evil-twin path is closed.
- **A deauthentication frame in a capture on a network with PMF required.** PMF makes the frame ineffective, which is the control.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `wireless-wifi-and-bluetooth-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `wireless-wifi-and-bluetooth-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: wireless-wifi-and-bluetooth-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-327 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](../wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](../wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](../wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `wireless-wifi-and-bluetooth-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/github_security_md (3), CYBER_CPT/ctftime (2), Forensic_Toolkit_Dataset (1), CYBER_CPT/mitre_attack_enterprise (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 1 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
