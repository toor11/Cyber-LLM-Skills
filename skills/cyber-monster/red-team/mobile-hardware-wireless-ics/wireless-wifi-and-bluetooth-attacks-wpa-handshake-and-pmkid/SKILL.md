---
name: wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid
description: WPA handshake and PMKID attacks. Covers capturing handshakes and PMKIDs, offline cracking strategy and the practical limits of each attack. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["wpa handshake", "pmkid attack", "wifi cracking"]
cwe: [CWE-327]
owasp: []
attack: []
capec: [CAPEC-604]
related: [wireless-wifi-and-bluetooth-attacks, wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin, wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble, android-app-security]
parent: wireless-wifi-and-bluetooth-attacks
---

# Wireless Wifi and Bluetooth Attacks Wpa Handshake and Pmkid - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

The WPA handshake capture techniques all serve one purpose: obtaining material from which a PSK can be tested offline. The four-way handshake provides the ANonce, SNonce, MAC addresses, and the MIC over a known EAPOL frame, so a candidate passphrase can be verified by deriving the PMK through PBKDF2 and checking the MIC — one hash and one HMAC per candidate, with no interaction with the AP. The PMKID, introduced in the RSN key data of the first EAPOL message on some implementations, allows the same offline test from a single frame with no client present. Neither technique breaks the cipher: they attack the passphrase's entropy, which is why the finding is "the passphrase space is small enough to search" rather than "WPA2 is broken". The practical variables are the passphrase policy, whether PMKID is exposed by the AP, and whether the captured material is from a PSK network at all — an Enterprise network yields nothing to test offline because the PMK comes from the RADIUS exchange. The defence is a passphrase whose entropy makes the search infeasible, plus PMF to prevent the deauthentication frames often used to force a re-handshake.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the network uses WPA2-Enterprise **THEN** there is nothing to test offline and this skill does not apply; the branch is certificate validation.
2. **IF** a capture contains a four-way handshake or a PMKID **THEN** the finding's strength is the passphrase entropy and nothing else.
3. **IF** the passphrase follows a policy that bounds the search space **THEN** compute the candidate count and compare it against a stated hashrate before calling it crackable.
4. **IF** the AP exposes a PMKID **THEN** an attacker needs no client present, which widens the window; the passphrase is still the control.
5. **IF** management-frame protection is required **THEN** the deauthentication lever is closed, which reduces the capture window without changing the entropy argument.
6. **IF** the question is the AP's configuration rather than the passphrase **THEN** start at [`wireless-wifi-and-bluetooth-attacks`](../wireless-wifi-and-bluetooth-attacks/SKILL.md).
7. **IF** a rogue AP is involved **THEN** switch to [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](../wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin/SKILL.md).
8. **IF** the passphrase is long and random and PMF is required **THEN** record `Verified Safe` with the entropy estimate and the PMF state.

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

1. **Confirm the network is PSK.** Read the AKM from the beacon. Enterprise means the offline path does not exist.
2. **Establish the capture's contents.** A complete four-way handshake, a partial one, or a PMKID. A partial capture is not testable and should not be reported as one.
3. **Choose the branch.** Small passphrase space, PMKID exposure, deauthentication-forced re-handshake, or a complete capture with an unknown space.
4. **Define the baseline-vs-probe differential.** Baseline: the passphrase policy as configured and evidenced by the organisation's rules. Probe: the entropy implied by the actual passphrase, if it can be established without cracking it — for example from a known policy violation. The differential is a search space smaller than the stated policy, and the report gives the candidate count and the hashrate.
5. **Name the stop condition.** Stop at the entropy calculation. Do not crack a production passphrase, and do not run a wordlist against a live capture.
6. **State the proof.** Report the AKM, the capture type, the PMKID presence, the policy, and the candidate count against a published hashrate. If the space is infeasible, record the negative with the arithmetic.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A complete four-way handshake in a capture | Offline-testable material exists, so the passphrase is the only control | EAPOL frames |
| A PMKID in the first EAPOL message | A single-frame offline test with no client present | RSN key data |
| `key_mgmt=WPA-PSK` on the AP | The network is PSK, so the offline path applies | AP configuration |
| `key_mgmt=WPA-EAP` on the AP | Enterprise, so the offline path does not exist | AP configuration |
| A passphrase policy requiring 12 characters from four classes | A search space in the `10^20` range, which is infeasible offline | Policy document |
| Management-frame protection required | Deauthentication-forced re-handshakes are blocked, which narrows the capture window | Beacon RSN capabilities |

## Worked Contrast

**Vulnerable: PSK with a short passphrase, PMKID exposed, no PMF**

```text
# Beacon: PSK only. The passphrase is a dictionary word with a year suffix, which
# the organisation's own documentation shows as the pattern in use.
RSN AKM: PSK
MFP: not required

# The first EAPOL message carries a PMKID, so no client is needed:
$ hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=1
PMKID dumped from AA:BB:CC:DD:EE:FF

# And the offline search:
$ hashcat -m 22000 dump.hc22000 wordlist.txt
```

**Hardened: long random passphrase, PMKID not exposed, PMF required**

```text
# Beacon: PSK with management-frame protection required. The passphrase is 20
# characters of random material, provisioned per site and stored in a vault.
RSN AKM: PSK
MFP: required

# No PMKID is returned by this AP, so a capture needs a client association, which
# PMF makes harder to force:
$ hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=1
(no PMKID in output)

# And the offline search against a captured handshake has no feasible outcome:
$ hashcat -m 22000 handshake.hc22000 --show
(no hashes cracked)
```

**Why this matters:** The left network's passphrase is searchable in a wordlist, the AP hands out a PMKID to any requester so no client is needed, and the absence of PMF lets an attacker force a re-handshake at will — three independent ways to obtain testable material for the same weak secret. The right network's passphrase makes the search infeasible, the AP does not expose a PMKID, and PMF blocks the forced re-handshake, so the capture either does not happen or does not matter.

## When It Is NOT This Issue

- **A WPA2-Enterprise network with captured EAPOL frames.** There is no PSK to test offline.
- **A partial handshake in a capture.** Not testable; the report should say the capture is incomplete rather than implying a weak passphrase.
- **A PSK network with a long random passphrase.** The offline path exists but its cost is infeasible; show the arithmetic.
- **A PMKID present in a lab capture from a test AP.** Not a production finding.
- **An old capture from a network whose passphrase has since rotated.** Historical exposure; the finding is the rotation record.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-327 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`wireless-wifi-and-bluetooth-attacks`](../wireless-wifi-and-bluetooth-attacks/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](../wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](../wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 5 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/github_security_md (2), CYBER_CPT/secwiki (2), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
