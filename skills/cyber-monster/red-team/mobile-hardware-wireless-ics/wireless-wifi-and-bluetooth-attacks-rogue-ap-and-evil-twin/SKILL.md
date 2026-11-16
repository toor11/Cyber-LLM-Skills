---
name: wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin
description: Rogue AP and evil twin attacks. Covers building rogue access points, captive portal credential capture and client deauthentication considerations. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["evil twin", "rogue ap", "captive portal", "deauth"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-604]
related: [wireless-wifi-and-bluetooth-attacks, wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid, wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble, android-app-security]
parent: wireless-wifi-and-bluetooth-attacks
---

# Wireless Wifi and Bluetooth Attacks Rogue Ap and Evil Twin - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

A rogue AP or evil twin works on the client's trust decision, not on the cipher. The malicious AP advertises an SSID the client already knows; when the client associates, the attacker either relays the EAP exchange to a real RADIUS server (so the inner credentials are what they steal), or terminates the TLS handshake itself and relies on the client not validating the server certificate, or simply serves DHCP and DNS to capture the traffic the client sends before any authentication completes. The three properties that make it work are: the client's willingness to associate with any BSSID claiming the SSID, the absence of server-certificate validation in the supplicant for Enterprise networks, and the absence of management-frame protection, which lets the attacker deauthenticate the client from the real AP to force a re-association. Against PSK networks the evil twin yields a handshake for offline testing rather than a live session; against Enterprise it can yield credentials, which is the more serious outcome. The controls are correspondingly specific: 802.1X server-certificate validation with a pinned CA and a domain-suffix match, PMF required, and for high-assurance deployments BSSID or channel binding where the client supports it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the network is WPA2-Enterprise and the client does not validate the server certificate **THEN** that is the finding; the evil twin yields credentials.
2. **IF** the network is PSK **THEN** the evil twin yields a handshake, so the entropy argument from the handshake skill applies instead.
3. **IF** management-frame protection is not required **THEN** the deauthentication path is open, which is the twin's forcing mechanism.
4. **IF** the client validates a pinned CA with a domain-suffix match **THEN** the twin fails at the TLS step unless it can present a valid certificate, which it cannot.
5. **IF** the question is the AP's own configuration **THEN** start at [`wireless-wifi-and-bluetooth-attacks`](../wireless-wifi-and-bluetooth-attacks/SKILL.md).
6. **IF** the question is the captured handshake rather than the twin **THEN** switch to [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](../wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid/SKILL.md).
7. **IF** every client validates the server certificate against a pinned CA with a suffix match and the APs require PMF **THEN** record `Verified Safe` with both facts.

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

1. **Establish the network's authentication model.** Enterprise or PSK. The twin's outcome differs entirely between them.
2. **Read the client's validation configuration.** `ca_cert`, `domain_suffix_match`, `subject_match`, and whether any of them is the system store alone. A system-store-only configuration is the finding for a corporate SSID.
3. **Check the PMF state.** Required, capable, or absent. Absent PMF gives the attacker a deauthentication lever.
4. **Define the baseline-vs-probe differential.** Baseline: the client associating with the real AP, which succeeds. Probe: the same client presented with a lab AP carrying the same SSID and a certificate that does not chain to the pinned CA. A client that completes the outer TLS handshake is the finding; one that aborts is the control.
5. **Name the stop condition.** Stop at the first lab client that completes the handshake without validating the certificate, or the first deauthentication that succeeds against PMF. Do not capture credentials.
6. **State the proof.** Report the SSID, the client configuration, the PMF state, and the handshake outcome. If every client validates against a pinned CA with a suffix match, record the negative with the configuration excerpt.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `ca_cert=` absent in a corporate supplicant profile | The client accepts any certificate, so the outer TLS step of an evil twin succeeds | wpa_supplicant, NetworkManager profile |
| `domain_suffix_match="corp.example.com"` present | The certificate must match the expected domain, which closes the twin path | wpa_supplicant profile |
| `MFP: not required` in the beacon | Deauthentication frames are honoured, so the attacker can force a re-association | Beacon RSN capabilities |
| A rogue BSSID advertising the corporate SSID from an unexpected location | The twin itself, visible in a wireless IDS | WIDS, monitor capture |
| A DHCP offer from an address outside the approved scope on the corporate SSID | The client received network parameters from an unauthorised server | DHCP monitoring |
| A client associating with a BSSID not in the approved list | The twin succeeded, which is the outcome signal | AP and WIDS logs |

## Worked Contrast

**Vulnerable: Enterprise client with no certificate validation and no PMF**

```text
# Client profile: the corporate SSID uses 802.1X but validates nothing.
network={
    ssid="corp-wifi"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="user@corp.example.com"
    password="..."
    # no ca_cert, no domain_suffix_match
}

# Beacon: management frames are unprotected.
RSN AKM: 802.1X
MFP: not required
```

```text
# So a lab AP with the same SSID completes the outer handshake and the client
# sends its inner identity and password hash.
```

**Hardened: pinned CA with a suffix match, and PMF required**

```text
# Client profile: the certificate must chain to the pinned CA and match the domain.
network={
    ssid="corp-wifi"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="user@corp.example.com"
    ca_cert="/etc/ssl/corp-root.pem"
    domain_suffix_match="radius.corp.example.com"
    domain_match="radius.corp.example.com"
}

# Beacon: management-frame protection required.
RSN AKM: 802.1X
MFP: required
```

**Why this matters:** The left client trusts any AP that claims the SSID, so a twin completes the outer TLS handshake and the client hands over its inner identity; the absent PMF means the attacker can force the client off the real AP. The right client requires a certificate from a pinned CA that matches a specific domain, and the required PMF means the deauthentication lever does not exist, so the twin cannot get either step.

## When It Is NOT This Issue

- **A client profile with `ca_cert` pointing to the system store for a public hotspot SSID.** Public networks have no organisational CA; the finding would be the SSID's classification.
- **A rogue AP advertising an SSID the organisation does not use.** Not a twin; a separate wireless-hygiene item.
- **A BSSID not in the approved list on a guest network with open authentication.** Open by design; the finding would be the guest network's isolation.
- **A deauthentication frame observed on a network with PMF required.** The frame is ineffective, which is the control.
- **A DHCP offer from a legitimate secondary server inside the approved scope.** Normal redundancy.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin
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
- [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](../wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/blackhills (2), CYBER_CPT/ctftime (2), OffsecCyber (1), CYBER_CPT/oxdf (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
