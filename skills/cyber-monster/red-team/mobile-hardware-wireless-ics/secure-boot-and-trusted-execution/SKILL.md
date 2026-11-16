---
name: secure-boot-and-trusted-execution
description: "Analyses secure boot and trusted execution: boot chain verification, key provisioning, TPM and secure element usage, and downgrade paths. Use when assessing device boot integrity."
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["secure boot bypass", "trusted execution", "tpm analysis", "boot chain"]
cwe: [CWE-347]
owasp: []
attack: []
capec: [CAPEC-578]
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
---

# Secure Boot and Trusted Execution - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

Secure boot review verifies a chain, so the finding is always the weakest link that the chain still trusts. A chain has a root of trust in immutable storage — a boot ROM, a one-time-programmable key hash, or a fuse — then each stage verifies the next before executing it, and the verification is a signature check over the stage's content with a key whose trust ultimately derives from the root. The failure modes are structural. The root may be a test or development key that shipped in production, which is what PKfail was: production AMI Aptio V firmware retained an AMI test Platform Key, so any attacker holding that leaked private key could sign a module the firmware would accept. The verification may cover only part of the stage, so an unsigned section is still loaded. The check may be skippable by a fault, which the side-channel skill covers. And the chain may terminate before a component that matters: a verified kernel that loads unsigned modules, or a verified bootloader that runs an unsigned recovery image. The review question is which link is weakest and whether the attacker can reach it, and the evidence is the key hash in the root, the verification call sites in each stage, and the list of components that are loaded without a check.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the root of trust holds a test, development, or vendor-shared key **THEN** that is the finding, and PKfail is the precedent for exactly this shape.
2. **IF** a stage is loaded without a signature check **THEN** the branch is the unsigned component, and its location in the boot order is the evidence.
3. **IF** the verification covers only part of the stage **THEN** the branch is partial coverage; the unsigned region is what an attacker modifies.
4. **IF** verification exists but is a single branch **THEN** add the fault analysis from [`side-channel-and-fault-injection`](../side-channel-and-fault-injection/SKILL.md).
5. **IF** the verified kernel loads unsigned modules or an unsigned recovery image **THEN** the branch is the terminal link, which is the most common practical bypass.
6. **IF** the finding is a debug interface that makes the chain irrelevant **THEN** start at [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md).
7. **IF** the root is a device-unique key in OTP, every stage is fully covered by a signature check, and no unsigned component loads **THEN** record `Verified Safe` with the three facts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the root.** A boot ROM, an OTP key hash, or a fuse. Read its value and compare against the expected production key, not against a vendor's default.
2. **Trace the chain stage by stage.** For each stage, the verification call, the region it covers, and the public key it uses. A stage with no call is the finding.
3. **Choose the branch.** Test or shared root key, unsigned stage, partial coverage, skippable check, or a terminal unsigned component.
4. **Define the baseline-vs-probe differential.** Baseline: a signed image boots and reports the expected measurement. Probe: the same image with one byte changed in an unsigned region, or with a stage re-signed by a test key. Acceptance on the probe is the finding.
5. **Name the stop condition.** Stop at the first stage whose modification is accepted. Do not flash a modified image to a production device; use a lab unit.
6. **State the proof.** Report the root key hash, the stage, the verification call or its absence, and the modified byte's offset. If every stage verifies, record the negative with the chain trace.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| An OTP key hash matching a vendor test key | A development root in production, which is the PKfail shape | Boot ROM, fuses |
| A stage loaded by a `load_image()` with no preceding signature check | An unsigned link in the chain, so that stage can be replaced | Bootloader code |
| A signature check over a header only, with the payload loaded separately | Partial coverage: the payload is unauthenticated | Bootloader code |
| A verified kernel that then loads modules without a signature | The chain terminates before a component that executes code | Kernel module loader |
| A recovery image path with no verification | A second entry point that bypasses the chain | Recovery partition |
| A full-chain measurement reported and compared to a signed manifest | The control, and the citation for a non-finding | TPM or secure element |

## Worked Contrast

**Vulnerable: production root holding a test key, and a recovery path with no verification**

```c
/* The boot ROM compares the first-stage hash against a key that is the same in
   every development and production unit. */
static const uint8_t otp_key_hash[32] = {
    0x3f, 0x8a, 0xc2, 0x1e, /* ... the vendor development key hash ... */
};

/* And the recovery path loads an image without checking it: */
if (recovery_requested()) {
    load_image(RECOVERY_PARTITION_ADDR, RECOVERY_PARTITION_SIZE);
    jump_to(RECOVERY_PARTITION_ADDR);      /* no verification */
}
```

**Hardened: device-unique root, every stage verified, no unverified recovery**

```c
/* The root is a per-device key hash burned at manufacture, so a leaked development
   key opens nothing. */
const uint8_t *otp_key_hash = otp_read_key_hash();   /* unique per device */

/* Every load path verifies first, including recovery. */
if (recovery_requested()) {
    if (!verify_signature(RECOVERY_PARTITION_ADDR, RECOVERY_PARTITION_SIZE,
                          otp_key_hash)) {
        halt_with_error(ERR_RECOVERY_SIG);
    }
    load_image(RECOVERY_PARTITION_ADDR, RECOVERY_PARTITION_SIZE);
    jump_to(RECOVERY_PARTITION_ADDR);
}
```

**Why this matters:** The left firmware trusts a key that is identical across every unit and ships an unverified recovery path, so a leaked development key or a modified recovery partition both yield code execution with the chain's blessing — which is exactly the PKfail failure mode. The right firmware roots trust in a per-device key so a shared key is worthless, and every load path including recovery verifies before it executes.

## When It Is NOT This Issue

- **A verified chain that reports a measurement mismatch on a development unit with test keys.** Expected; confirm the SKU.
- **An unsigned component in a partition the chain never executes.** The chain does not reach it.
- **A recovery path that requires physical presence and verifies after load with a rollback on failure.** Weaker than verify-before-load but not the same finding; state the ordering.
- **A vendor key that is unique per device but provisioned in a shared facility.** The custody question, not the chain.
- **Secure boot disabled on a device whose debug port is also disabled and whose flash is encrypted.** The other controls still bound the exposure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `secure-boot-and-trusted-execution` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `secure-boot-and-trusted-execution` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: secure-boot-and-trusted-execution
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-347 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `secure-boot-and-trusted-execution` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 18 |
| Distinct dataset sources | 13 |
| Top sources | SecEval/apple_platform_security (3), SecEval/android_sec_doc (2), cyber-security/CyberSec-Dataset (2), CYBER_CPT/ctftime (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
