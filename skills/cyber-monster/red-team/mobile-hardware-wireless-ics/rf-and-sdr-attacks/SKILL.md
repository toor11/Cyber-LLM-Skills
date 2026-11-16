---
name: rf-and-sdr-attacks
description: "Analyses and attacks radio frequency systems with SDR: signal capture and decoding, replay, jamming considerations and proprietary protocol reverse engineering. Use when the target uses RF for control or telemetry."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["sdr", "rf attack", "signal replay", "radio hacking", "hackrf"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-604]
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
---

# RF and SDR Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

RF and SDR review is about what a receiver believes without authentication. A radio link carries no identity unless the protocol puts one there, so a receiver that accepts a replay of a previously captured transmission, or a transmission synthesised from a known encoding, is doing exactly what it was designed to do. The mechanisms that matter for review are: fixed-code remotes, where a captured frame replays forever and the finding is the absence of a rolling code; rolling-code systems with a weakness in the counter or the keystream, where a recorded pair can be replayed within the window; simple OOK or FSK links where the bits are recoverable from a capture and the payload has no MAC; and protocols with a real cryptographic layer, where the finding is a configuration or key-management defect rather than the modulation. GNU Radio and a receive-only SDR are the review tools: they record, demodulate, and decode, and they do not transmit. The discipline is that a finding is a demonstrated difference between a legitimate transmission and a replay or a synthesised one, observed at the receiver, and that transmission is out of scope unless the engagement explicitly authorises it on a shielded setup.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the remote uses a fixed code **THEN** a capture replays forever, which is the finding; a rolling code is the control.
2. **IF** the protocol has a rolling counter **THEN** check the acceptance window: how many counter values the receiver will accept out of order decides replay feasibility.
3. **IF** the modulation is OOK or FSK with no MAC **THEN** the payload is fully recoverable from a capture, and the finding is the absence of authentication.
4. **IF** the protocol has a cryptographic layer **THEN** the branch is key management, not modulation.
5. **IF** the question is a wireless data network rather than a remote link **THEN** start at [`wireless-wifi-and-bluetooth-attacks`](../wireless-wifi-and-bluetooth-attacks/SKILL.md).
6. **IF** the target is an automotive key fob **THEN** the branch is rolling-code and relay, and the automotive skill covers the bus side.
7. **IF** every transmission carries a rolling counter with a narrow acceptance window and a MAC **THEN** record `Verified Safe` with the captured frame analysis.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Characterise the link.** Frequency, modulation, symbol rate, and whether the payload repeats across transmissions. A capture of two presses answers most of it.
2. **Decode the payload.** With a decoder suited to the modulation, recover the bits and compare two captures. A payload that is identical across presses is a fixed code; one that changes in a counter field is a rolling code.
3. **Choose the branch.** Fixed code, wide acceptance window, no MAC, or weak key management.
4. **Define the baseline-vs-probe differential.** Baseline: a legitimate transmission received and decoded, which produces the expected action. Probe: the same transmission replayed from a recording, or a synthesised frame with one field changed, presented to the receiver. The action occurring on the probe is the finding, and it must be demonstrated on a shielded lab setup.
5. **Name the stop condition.** Stop at the first replayed frame the receiver accepts. Do not transmit outside a shielded enclosure, and do not test against a live installation.
6. **State the proof.** Report the frequency, modulation, the decoded fields, the difference between captures, and the receiver's response. If the receiver rejects the replay, record the negative with the counter state that rejected it.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| Two captures of the same button press with identical payloads | A fixed code, so a recording replays indefinitely | OOK/FSK capture |
| Two captures with only a counter field differing | A rolling code, and the counter's width bounds the window | Decoded payload |
| A receiver accepting a counter value two steps behind its own | A wide acceptance window, which makes replay feasible | Receiver behaviour |
| A payload with no MAC or checksum beyond a static one | No authentication, so any node can synthesise a frame | Frame layout |
| A capture decodable with a public decoder and no key | No cryptographic layer at all | Decoder output |
| A rolling counter with a narrow window and a MAC | The control, and the citation for a non-finding | Receiver behaviour, frame layout |

## Worked Contrast

**Vulnerable: fixed-code remote with no MAC and a receiver that accepts any repeat**

```text
# Two captures of the same button: identical payloads.
$ rtl_433 -f 433.92M -R 0 -A  # capture to a file, then compare
$ python - <<'PY'
a = open("press1.cu8","rb").read()
b = open("press2.cu8","rb").read()
print("identical:", a == b)      # True on a fixed-code remote
PY
identical: True

# And the decoded frame has a static check field only:
payload: 10110011 01011100 00000000 11111111
        (prefix)  (button) (unused) (static check)
```

**Hardened: rolling counter with a narrow window and a MAC**

```text
# Two captures differ in a counter field, and the frame carries a MAC:
payload: 10110011 01011100 00000101 10110101
        (prefix)  (button) (counter) (mac8)

# The receiver's own log shows it rejecting an out-of-window counter:
rx: counter=5 mac=OK action=lock
rx: counter=3 mac=OK action=REJECTED reason=counter_out_of_window
rx: counter=5 mac=OK action=REJECTED reason=replay
```

**Why this matters:** The left remote's frame is a constant, so any recording of one press operates the receiver forever and a synthesised frame with a different button works just as well. The right remote advances a counter that the receiver validates within a narrow window and authenticates with a MAC, so a replayed frame is rejected twice over — once for the counter and once for the replay record.

## When It Is NOT This Issue

- **A fixed-code remote on a device with no security consequence, such as a mains switch.** The classification decides; state it.
- **A rolling-code receiver that rejects a replay in the lab.** That is the control and the negative result to report.
- **A capture that cannot be decoded without a key.** The cryptographic layer is present; the branch becomes key management.
- **A relay finding rather than a replay finding.** Relaying a live transmission is a different mechanism; report it as such.
- **A test transmission inside a shielded enclosure that the receiver accepted.** That is the proof, not a finding about the environment.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `rf-and-sdr-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `rf-and-sdr-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: rf-and-sdr-attacks
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `rf-and-sdr-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/blackhills (5), CYBER_CPT/nuclei_templates (2), CYBER_CPT/infocon (1), CYBER_CPT/atomic_red_team (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
