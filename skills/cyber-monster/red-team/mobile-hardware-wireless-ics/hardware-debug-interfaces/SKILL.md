---
name: hardware-debug-interfaces
description: "Finds and uses hardware debug interfaces: UART, JTAG, SWD and SPI flash access, pin identification and console recovery. Use when physically assessing an embedded device."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["uart", "jtag", "swd", "hardware debug", "serial console", "spi flash"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-116]
related: [hardware-debug-interfaces-uart-and-serial, hardware-debug-interfaces-jtag-and-swd, android-app-security, ios-app-security]
---

# Hardware Debug Interfaces - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

Debug interface review is about what a physical or near-field attacker can reach without authentication. Every SoC exposes a set of them and each has a different guard. UART is a two-wire serial console that frequently drops into a root shell or a bootloader prompt, and the guard is either a disabled console, a password on the bootloader, or a physical trace that is not populated. JTAG and SWD are the debug transport for the CPU itself: they read and write memory, halt the core, and read out flash, and the guard is a fuse that disables the TAP, a secure-boot chain that refuses to run modified images, and physical obscurity of the header. SPI and I2C flash chips are readable with a clip: the guard is encryption at rest with a key held by the SoC, and a read-out protection bit. eMMC and NAND have their own read-out protections and their own known weaknesses. The review question is not "is there a header" but "what does access to that header yield", and the answer requires knowing whether secure boot, flash encryption, and debug authentication are enabled together, because any one of them alone leaves a path.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the finding is a UART console that reaches a shell or a bootloader prompt **THEN** that is the finding; the escalation is what that shell can do, which is the secure boot question.
2. **IF** the interface is JTAG or SWD **THEN** switch to [`hardware-debug-interfaces-jtag-and-swd`](../hardware-debug-interfaces-jtag-and-swd/SKILL.md).
3. **IF** the interface is a serial console specifically **THEN** switch to [`hardware-debug-interfaces-uart-and-serial`](../hardware-debug-interfaces-uart-and-serial/SKILL.md).
4. **IF** the device has secure boot and flash encryption enabled with debug authentication locked **THEN** a populated header is a hardening note rather than a finding; say which of the three is present.
5. **IF** the finding is a flash chip readable by clip **THEN** the branch is at-rest protection, and the key custody is what decides it.
6. **IF** the target is firmware content rather than the interface **THEN** start at [`firmware-extraction-and-emulation`](../firmware-extraction-and-emulation/SKILL.md).
7. **IF** the target is a secure boot chain rather than a debug header **THEN** start at [`secure-boot-and-trusted-execution`](../secure-boot-and-trusted-execution/SKILL.md).
8. **IF** every interface is disabled or requires authentication, and flash is encrypted with a device-bound key **THEN** record `Verified Safe` with all three facts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `hardware-debug-interfaces-uart-and-serial` | [`hardware-debug-interfaces-uart-and-serial`](../hardware-debug-interfaces-uart-and-serial/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `hardware-debug-interfaces-jtag-and-swd` | [`hardware-debug-interfaces-jtag-and-swd`](../hardware-debug-interfaces-jtag-and-swd/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory the interfaces.** Physical headers, test pads, unpopulated footprints, and any documented debug connector. Photograph and measure rather than probing blindly.
2. **Classify what each interface yields.** A shell, a bootloader prompt, memory read/write, flash read, or only a log stream. The class decides the finding.
3. **Establish the guards.** Secure boot state, flash encryption state, debug authentication fuses, and any bootloader password. These three decide whether interface access is equivalent to device compromise.
4. **Define the baseline-vs-probe differential.** Baseline: the device's normal boot and its console output. Probe: the same boot with the interface attached and a keystroke sent. A prompt that accepts input where the baseline showed only logs is the finding.
5. **Name the stop condition.** Stop at the first interactive prompt or the first successful flash read. Do not modify the device, and do not attempt to disable a fuse.
6. **State the proof.** Report the interface, the pinout, the prompt or read result, and the guard state. If access yields only logs and the flash is encrypted with a device-bound key, record the negative with the fuse state.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A 4-pin header with a 115200-baud console that accepts input | A UART shell, which is the most common physical compromise path | Device PCB, bootloader |
| A bootloader prompt that accepts `printenv` and `setenv` | Control over the kernel command line, so `init=/bin/sh` is available | U-Boot, barebox |
| An unpopulated JTAG footprint next to the SoC | A debug transport that may or may not be fused off | PCB inspection |
| `efuse` read showing secure boot enabled and debug disabled | The guards are on, so interface access does not yield code execution | SoC fuses, secure boot state |
| A flash chip readable with a SOIC clip returning plaintext strings | No at-rest encryption, so the filesystem is readable offline | SPI NOR flash |
| A console that prints logs but rejects input | A log-only interface, which is a hardening note not a compromise | Bootloader console configuration |

## Worked Contrast

**Vulnerable: UART console with a shell, no bootloader password, unencrypted flash**

```text
# Attaching to the populated 4-pin header at 115200 baud:
U-Boot 2023.10 (Jan 15 2024 - 09:12:44 +0000)
Hit any key to stop autoboot:  0
=> printenv bootargs
bootargs=console=ttyS0,115200 root=/dev/mmcblk0p2 rw
=> setenv bootargs ${bootargs} init=/bin/sh
=> boot
# ... and the device boots to a root shell with no authentication.

# The flash image, read with a clip, contains plaintext credentials:
$ strings flash.bin | rg -i "password|token=" | head -3
```

**Hardened: console limited to logs, bootloader locked, flash encrypted with a device key**

```text
# The bootloader is built with a console that ignores input and a locked environment:
U-Boot 2023.10 (Jan 15 2024 - 09:12:44 +0000)
Hit any key to stop autoboot:  0
=> printenv bootargs
## Error: "printenv" not defined          # command set removed at build time
Loading kernel from encrypted partition...

# The flash read returns ciphertext:
$ xxd -l 64 flash.bin
00000000: 3f8a c21e 7b04 9d55 a1f0 2c8b 6e33 07da  ?...{..U..,.n3..
```

```text
# Fuse state, read from a signed diagnostic image:
secure_boot_enabled = 1
flash_encryption_enabled = 1
debug_authentication = locked
```

**Why this matters:** The left device gives a root shell through a physically accessible header and stores credentials in plaintext on a chip anyone can clip, so the finding needs no vulnerability at all. The right device ships a console that cannot be interrupted, a bootloader whose command set is compiled out, an encrypted flash whose key never leaves the SoC, and fuses that disable the debug transport.

## When It Is NOT This Issue

- **A UART header that prints logs and ignores input.** A log console is a diagnostic, not a compromise.
- **A populated JTAG header on a device with debug authentication locked.** The header exists but the TAP is fused off; state the fuse.
- **An unpopulated footprint with no accessible pads.** Not reachable without rework beyond the threat model.
- **A flash chip whose contents are ciphertext.** At-rest encryption is the control; the finding would be the key custody.
- **A documented service port that requires an authenticated session.** A deliberate interface with a guard.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `hardware-debug-interfaces` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `hardware-debug-interfaces` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: hardware-debug-interfaces
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`hardware-debug-interfaces-uart-and-serial`](../hardware-debug-interfaces-uart-and-serial/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`hardware-debug-interfaces-jtag-and-swd`](../hardware-debug-interfaces-jtag-and-swd/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `hardware-debug-interfaces` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/awesome_list (6), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
