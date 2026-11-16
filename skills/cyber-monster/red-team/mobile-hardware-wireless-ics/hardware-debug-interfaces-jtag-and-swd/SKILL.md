---
name: hardware-debug-interfaces-jtag-and-swd
description: JTAG and SWD access. Covers identifying JTAG and SWD headers, using OpenOCD, and dumping or debugging firmware over the debug port. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["jtag debug", "swd openocd", "debug port"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-116]
related: [hardware-debug-interfaces, hardware-debug-interfaces-uart-and-serial, android-app-security, ios-app-security]
parent: hardware-debug-interfaces
---

# Hardware Debug Interfaces Jtag and Swd - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

JTAG and SWD are the CPU's own debug transport, so access to them is access to the core: halt, single-step, read and write memory, read and write registers including the debug authentication registers, and often read out the entire flash. The interface is a small set of signals — TCK/TMS/TDI/TDO for JTAG, SWDIO/SWCLK for SWD — and a target that responds to an IDCODE read is a target whose TAP is enabled. The guards are layered and each layer has a specific failure. A fuse or one-time-programmable bit can disable the TAP, and the check is whether the read returns an IDCODE or an error. Debug authentication can require a challenge-response with a key, which is ARM's authenticated debug model and is only effective if the key is not in the firmware. Read-out protection on the flash controller can block bulk reads while leaving the core haltable, which is a partial guard and often enough to defeat. Secure boot decides what happens if an attacker writes modified code. The review question is which of these is present, and the evidence is an IDCODE response and a flash read attempt rather than the presence of a header.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an IDCODE read succeeds on a header **THEN** the TAP is enabled; the next question is whether debug authentication gates it.
2. **IF** the core halts and memory reads succeed **THEN** the finding is memory access, which reaches keys in RAM.
3. **IF** debug authentication requires a challenge-response **THEN** check where the key lives; a key in firmware makes the guard nominal.
4. **IF** read-out protection blocks the flash read but the core is haltable **THEN** the branch is partial protection, which is still a finding for key extraction.
5. **IF** the interface is a serial console rather than a debug transport **THEN** switch to [`hardware-debug-interfaces-uart-and-serial`](../hardware-debug-interfaces-uart-and-serial/SKILL.md).
6. **IF** the device has secure boot and debug locked with a device-bound key **THEN** record the hardening note with the IDCODE result and the fuse state.
7. **IF** the header is present but no target responds **THEN** the TAP is fused off, which is the control; state the fuse evidence.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the header.** Five or ten pads in the standard JTAG/SWD arrangement, or a documented connector. Continuity to ground on pin 1 and the ARM-standard pinout are the usual confirmation.
2. **Attempt an IDCODE read.** `openocd` with the interface config reports a target or an error. A target is the finding's precondition; an error about a locked device is the guard.
3. **Classify the guard.** TAP disabled, debug authentication required, read-out protection only, or nothing.
4. **Define the baseline-vs-probe differential.** Baseline: the IDCODE read on a known-unlocked development unit. Probe: the same read on the production unit. A target on the production unit where the development unit also responds is expected; the finding is that the production unit responds at all when the design intends it not to.
5. **Name the stop condition.** Stop at the first successful halt or memory read. Do not dump a production flash or extract keys.
6. **State the proof.** Report the header, the pinout, the IDCODE value, the guard state, and what the read yielded. If the TAP is disabled, record the negative with the error and the fuse state.

## Concrete Patterns

| Indicator | What it proves | Stack or surface |
|---|---|---|
| `Info : JTAG tap: stm32f4x.cpu tap/device found: 0x4ba00477` | The TAP is enabled, which is the precondition for every debug operation | OpenOCD output |
| `Error: Target not examined yet` or a locked-device message | The TAP is disabled or the device is protected, which is the control | OpenOCD output |
| A halt followed by a successful memory read at a known address | Core access, which reaches keys and configuration in RAM | Debugger console |
| A flash read that returns 0x00 or 0xFF across the whole region | Read-out protection blocking the read, which is a partial guard | Flash programmer |
| `DBGMCU` or `DHCSR` registers writable and reporting a halted core | Debug authentication is absent, so nothing gates the transport | Register view |
| A challenge-response prompt before the TAP unlocks | Authenticated debug, which is a real control when the key is not in firmware | ARM authenticated debug |

## Worked Contrast

**Vulnerable: TAP enabled, core haltable, flash readable, debug key in firmware**

```text
$ openocd -f interface/ftdi.cfg -f target/stm32f4x.cfg
Info : JTAG tap: stm32f4x.cpu tap/device found: 0x4ba00477 (mfg: 0x23b, part: 0xba00, ver: 0x4)
Info : starting gdb server for stm32f4x.cpu on 3333
> halt
target halted due to debug-request, current mode: Thread
> mdw 0x20000000 4
0x20000000: 3f8ac21e 7b049d55 a1f02c8b 6e3307da
> flash read_bank 0 dump.bin
```

```c
/* Guard present only in name: the authentication key is a constant in flash. */
static const uint8_t dbg_key[16] = {0x3f,0x8a,0xc2,0x1e, /* ... */};
```

**Hardened: TAP fused off, authenticated debug with a device-bound key, protected flash**

```text
$ openocd -f interface/ftdi.cfg -f target/stm32f4x.cfg
Info : datacount=2 progbufsize=8
Error: expected 0x2ba01477, got 0x00000000     # no TAP response: transport disabled
Error: JTAG scan chain interrogation failed

$ minipro -p "W25Q64" -r dump.bin
Reading... 0x000000-0x7FFFFF: 0xFF ...          # read-out protection returns erased data
```

```text
# The device's own diagnostic output reports the guard state:
debug_transport = disabled (OPTION byte 0x7F)
readout_protection = level 2
authenticated_debug = required, key = device HUK
```

**Why this matters:** The left device answers a JTAG interrogation, halts, exposes RAM, and reads its flash, and the debug key it would ask for is a constant in the same flash — so the interface is effectively unguarded. The right device returns no TAP response, its flash controller returns erased data under level-2 read-out protection, and authenticated debug would require a key derived from a hardware unique key the attacker cannot read.

## When It Is NOT This Issue

- **A header present with no TAP response.** The transport is disabled; the header is a leftover footprint.
- **Read-out protection at level 1 with a haltable core on a development unit.** Development units are expected to be open; confirm the SKU.
- **Authenticated debug requiring a challenge-response with a device-bound key.** That is the strongest available guard.
- **A locked device that still reports an IDCODE but refuses halt.** The TAP responds but debug authentication gates the operation, which is the intended model.
- **A test pad that looks like JTAG but carries a different bus.** Confirm with an IDCODE read before filing.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `hardware-debug-interfaces-jtag-and-swd` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `hardware-debug-interfaces-jtag-and-swd` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: hardware-debug-interfaces-jtag-and-swd
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`hardware-debug-interfaces-uart-and-serial`](../hardware-debug-interfaces-uart-and-serial/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `hardware-debug-interfaces-jtag-and-swd` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/oxdf (10), CYBER_CPT/github_security_md (3), CYBER_CPT/hacktricks (3), CYBER_CPT/awesome_list (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
