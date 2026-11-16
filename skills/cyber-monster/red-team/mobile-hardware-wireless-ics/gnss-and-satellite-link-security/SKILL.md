---
name: gnss-and-satellite-link-security
description: Assesses GNSS receiver resilience (OSNMA/Galileo authentication, C/N0 jump & clock-drift spoofing detection) and satellite/embedded telemetry modem framing security. Use when reviewing navigation-dependent or satcom-connected systems.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["gnss spoofing detection", "gps authentication osnma", "satcom modem security"]
cwe: [CWE-290, CWE-345]
owasp: []
attack: []
capec: []
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
corpus_sparse: true
---

# Gnss and Satellite Link Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

GNSS security review starts from the fact that the civil signals are unauthenticated by design: a receiver correlates against a known spreading code and solves for position and time from the navigation message, and nothing in the legacy signal proves the message came from a satellite. Jamming floods the band and denies the service; spoofing transmits a counterfeit signal that the receiver locks onto, which can move the reported position or, more dangerously for infrastructure, shift the reported time. Two mitigations exist today and they differ in what they prove. Navigation Message Authentication authenticates the navigation data: Galileo's OSNMA, declared operational on 24 July 2025, embeds a TESLA-based authentication scheme in reserved fields of the E1-B I/NAV message so a receiver can verify that the ephemeris and timing parameters came from Galileo and were not modified — it does not prevent spoofing or jamming, it makes spoofing detectable, and it requires receiver-side implementation plus certified public keys from the European GNSS Service Centre. Ranging authentication, which Galileo's Signal Authentication Service is planned to provide, would protect the pseudorange itself. The review question is which of these the receiver implements, whether the rest of the system treats GNSS time and position as trusted input, and what a position shift would affect.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the receiver does not implement OSNMA **THEN** the branch is unauthenticated navigation data, and the finding is the trust placed in it.
2. **IF** the receiver implements OSNMA **THEN** check that the public keys are the certified ones from the GSC and that the verification result gates the position output.
3. **IF** the system uses GNSS time for a security decision **THEN** that is the highest-severity branch, because a time shift can affect certificate validity or log ordering.
4. **IF** the system uses GNSS position for a safety or financial decision **THEN** the branch is the cross-check: an independent source, a geofence, or a plausibility rule.
5. **IF** the finding is the RF link itself **THEN** start at [`rf-and-sdr-attacks`](../rf-and-sdr-attacks/SKILL.md) for the capture method.
6. **IF** the finding is a device that receives GNSS and reports over a network **THEN** start at [`iot-device-exploitation`](../iot-device-exploitation/SKILL.md) for the device surfaces.
7. **IF** the receiver verifies OSNMA with certified keys and the system cross-checks time and position against an independent source **THEN** record `Verified Safe` with both facts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish what the receiver supports.** OSNMA capability, the firmware version, and whether the verification result is exposed to the application. A capability that is not consumed is not a control.
2. **Trace what the system does with the output.** Position into a geofence, time into a certificate check, or both into a log. The consumer decides severity.
3. **Choose the branch.** No authentication, unverified OSNMA, unauthenticated time used for a decision, or unauthenticated position used for a decision.
4. **Define the baseline-vs-probe differential.** Baseline: a receiver in an open-sky location reporting a stable position and time. Probe: the same receiver with a recorded or synthesised signal presented in a shielded setup. A position or time shift that the application accepts is the finding; an OSNMA verification failure is the control.
5. **Name the stop condition.** Stop at the first application decision that consumes unverified position or time. Do not transmit a spoofing signal outside a shielded enclosure.
6. **State the proof.** Report the receiver model, the OSNMA state, the key source, the consumer of the output, and the decision it affects. If OSNMA is verified with certified keys and the consumer cross-checks, record the negative with both.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A receiver with no OSNMA support in its firmware or datasheet | Navigation data is unauthenticated, so a spoofed signal is indistinguishable | Receiver specification |
| `OSNMA` present but the verification result not consumed by the application | A capability that is not a control | Receiver API, application code |
| GNSS time used to validate a certificate or to order log entries | The highest-severity consumption, because a time shift changes a security decision | Application code |
| A position used for a geofence or a billing decision with no cross-check | Unauthenticated position driving a business rule | Application code |
| OSNMA verified with keys from the European GNSS Service Centre | Authenticated navigation data, which is the control | Receiver configuration |
| An independent time source or a second constellation cross-check | The redundancy control for the consumer | System architecture |

## Worked Contrast

**Vulnerable: unauthenticated GNSS time driving a certificate check, no OSNMA**

```python
# The service takes its clock from the GNSS receiver and uses it to decide whether a
# certificate is still valid. Nothing authenticates the navigation data.
import datetime
from gnss import read_time        # returns receiver-reported UTC

def verify_cert(cert) -> bool:
    now = read_time()             # unauthenticated, attacker-influenceable
    return cert.not_valid_before <= now <= cert.not_valid_after
```

**Hardened: OSNMA-verified data, and time cross-checked against an independent source**

```python
# The receiver verifies OSNMA against GSC public keys, and the service refuses to
# advance its clock beyond a bounded drift from an independent source.
import datetime
from gnss import read_time_with_osnma, OsnmaError
from ntp import trusted_utc

MAX_DRIFT = datetime.timedelta(seconds=2)

def verify_cert(cert) -> bool:
    try:
        gnss_now, verified = read_time_with_osnma()      # raises if unauthenticated
    except OsnmaError:
        gnss_now, verified = None, False
    reference = trusted_utc()
    if not verified or gnss_now is None or abs(gnss_now - reference) > MAX_DRIFT:
        raise RuntimeError("time source not trustworthy")
    return cert.not_valid_before <= reference <= cert.not_valid_after
```

**Why this matters:** The left service trusts a value an attacker within radio range can shift, so a spoofed time can make an expired certificate appear valid or a valid one appear expired. The right service refuses to use GNSS time unless OSNMA verified the navigation data and the value agrees with an independent source within a bounded drift, so a spoofed signal is detected rather than consumed.

## When It Is NOT This Issue

- **A receiver used only for a display of position with no automated decision.** No consumer, no finding.
- **A device with no OSNMA but an independent time source used for every security decision.** The GNSS is informational.
- **An OSNMA failure during a known test in a shielded enclosure.** That is the control firing.
- **A jamming event, which is a denial of service rather than a spoofing finding.** Report the availability impact separately.
- **A receiver in a fixed installation with a surveyed position checked against a geofence.** The cross-check is the control.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `gnss-and-satellite-link-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `gnss-and-satellite-link-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: gnss-and-satellite-link-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-290, CWE-345 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `gnss-and-satellite-link-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-290, CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
