---
name: side-channel-and-fault-injection
description: "Applies side-channel and fault techniques: power and EM analysis, timing attacks and voltage or clock glitching to extract secrets or bypass checks. Use when hardware-level analysis is in scope."
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["side channel", "power analysis", "fault injection", "glitching", "timing attack hardware"]
cwe: [CWE-1300]
owasp: []
attack: []
capec: [CAPEC-606]
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
---

# Side Channel and Fault Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

Side-channel and fault-injection review asks whether a secret-dependent physical property is observable, and whether an induced fault can bypass a check. On the side-channel side the mechanisms are power consumption (a correlation power analysis over a cryptographic operation recovers a key byte by byte), electromagnetic emanation (the same information from a near-field probe, with better locality), and timing (already covered by the constant-time skill, but the arithmetic path here can also leak through cache and branch behaviour). On the fault side the mechanisms are clock or voltage glitching, which can cause a conditional branch to be skipped — a signature check that returns true, a secure boot verification that is bypassed, a PIN comparison that succeeds — and laser or body-biasing faults, which need die access. The precondition for both is physical access to the device and, for a meaningful finding, a secret worth recovering or a check worth skipping. The review's job is to identify which of the device's operations has an unprotected secret-dependent path and which check lacks a redundant verification, and to say what an attacker with lab equipment would gain — not to perform the attack.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a key or PIN comparison is a single conditional branch **THEN** the branch is fault-skippable, and the control is a redundant check with a randomised or duplicated decision.
2. **IF** the cryptographic implementation is on a general-purpose core with no masking **THEN** the branch is power analysis, and the control is a masked or a hardware-accelerated path.
3. **IF** the device has a secure element or a hardware crypto accelerator **THEN** the side-channel exposure drops sharply; record the part and its certification.
4. **IF** the finding is a timing leak in software **THEN** switch to [`constant-time-and-crypto-side-channel-code-audit`](../../cryptography-attacks/constant-time-and-crypto-side-channel-code-audit/SKILL.md).
5. **IF** the finding is a secure boot check that could be skipped **THEN** start at [`secure-boot-and-trusted-execution`](../secure-boot-and-trusted-execution/SKILL.md) for the chain.
6. **IF** the device is a smart card or a secure element **THEN** the certification level is the argument; state the part and its evaluation.
7. **IF** the secret is not worth recovering or the check does not protect anything **THEN** record `Not Applicable` with the reasoning, rather than a theoretical finding.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the secret-dependent operation.** Key derivation, a PIN comparison, a signature, or a secure boot verification. Only an operation whose result depends on a secret is in scope.
2. **Classify the hardware.** General-purpose core, hardware crypto accelerator, or secure element. The class decides whether a software countermeasure is the only option.
3. **Choose the branch.** Power or EM analysis exposure, fault-skippable check, missing redundancy, or an unprotected debug path that makes either trivial.
4. **Define the baseline-vs-probe differential.** Baseline: the operation performed normally, with its timing and power profile recorded. Probe: the same operation repeated with randomised inputs and averaged. A profile that separates on a secret-dependent variable is the exposure; for a fault, the differential is a check that returns success under an induced condition.
5. **Name the stop condition.** Stop at the demonstration of a secret-dependent separation in the recorded traces, or at the identification of a single-branch check with no redundancy. Do not attempt key recovery or fault injection on production hardware.
6. **State the proof.** Report the operation, the hardware class, the measured or structural exposure, and the countermeasure. If the operation runs in a certified secure element, record the negative with the part number and its evaluation level.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A single `if (memcmp(pin, stored, len) == 0)` in the authentication path | One branch decides the outcome, so a glitch that skips it grants access | Firmware, bare-metal C |
| An AES implementation in software on a Cortex-M0 with no masking | A power-analysis target, recoverable with a few thousand traces | Firmware, general-purpose core |
| A hardware crypto accelerator or secure element handling the key | The key never enters the general-purpose core, which is the control | SoC datasheet |
| A secure boot check followed by a second, independent verification | Redundancy against fault injection, which is the control | Bootloader code |
| A debug port enabled during the cryptographic operation | The cheapest path to the same secret, which supersedes the side-channel argument | Debug configuration |
| A PIN attempt counter in RAM only | A fault or a reset restores the counter, so the lockout is bypassable | Firmware |

## Worked Contrast

**Vulnerable: PIN comparison as one branch, counter in RAM, software AES on a general core**

```c
/* One comparison decides, the attempt counter is plain RAM, and the AES runs in
   software with the key in ordinary memory. */
static uint8_t attempts;
static uint8_t aes_key[16];

bool check_pin(const uint8_t *pin) {
    if (attempts >= 3) return false;
    if (memcmp(pin, stored_pin, 4) == 0) {      /* a single skippable branch */
        attempts = 0;
        return true;
    }
    attempts++;                                  /* reset by a power cycle */
    return false;
}

void encrypt(uint8_t *buf) {
    aes_software(aes_key, buf);                  /* key in RAM, no masking */
}
```

**Hardened: redundant check, counter in protected storage, key in a secure element**

```c
/* The decision requires two independent comparisons, the counter lives in protected
   storage with a monotonic property, and the key never enters the CPU. */
bool check_pin(const uint8_t *pin) {
    if (protected_counter_read() >= 3) return false;
    /* Two independent comparisons with different implementations. */
    bool a = ct_compare(pin, stored_pin, 4);
    bool b = ct_compare_alt(pin, stored_pin, 4);
    if (a && b) {
        protected_counter_reset();
        return true;
    }
    protected_counter_increment();
    return false;
}

void encrypt(uint8_t *buf) {
    se_aes_encrypt_in_place(buf);    /* key held in the secure element */
}
```

**Why this matters:** The left device can be opened by a single voltage glitch that skips one comparison, its lockout resets with a power cycle, and its key is recoverable from power traces because the AES runs on the general core. The right device requires two independent comparisons to agree, keeps the attempt counter in protected storage where a reset does not clear it, and delegates the key operation to a secure element so the trace carries no key-dependent signal.

## When It Is NOT This Issue

- **A cryptographic operation inside a certified secure element.** The evaluation level is the argument; state the part.
- **A single comparison on a non-secret value.** Nothing to skip that matters.
- **A device with no physical access path, in a sealed enclosure with tamper response.** The access precondition is absent.
- **A theoretical power-analysis exposure with no secret worth recovering.** Not applicable; say why.
- **A glitch finding on a development board with no secure boot.** The board is not the product.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `side-channel-and-fault-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `side-channel-and-fault-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: side-channel-and-fault-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1300 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `side-channel-and-fault-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1300`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/ctf_search (5), CYBER_CPT/hacktricks (4), bugbounty-hunter-v1 (1), ctf-solver-dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 11 cases |
| Grounding | multi-dataset corpus-grounded |
