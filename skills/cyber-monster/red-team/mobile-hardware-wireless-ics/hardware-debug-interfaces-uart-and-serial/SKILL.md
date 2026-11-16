---
name: hardware-debug-interfaces-uart-and-serial
description: UART and serial console access. Covers locating UART pads, determining baud rate, obtaining boot logs and reaching a root console. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: mobile-hardware-wireless-ics
tier: leaf
triggers: ["uart console", "serial console", "baud detection"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-116]
related: [hardware-debug-interfaces, hardware-debug-interfaces-jtag-and-swd, android-app-security, ios-app-security]
parent: hardware-debug-interfaces
---

# Hardware Debug Interfaces Uart and Serial - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

A UART console is the highest-yield interface in device review because it costs two wires and returns a shell more often than not. The console is configured in the bootloader and in the kernel command line: `console=ttyS0,115200` in the kernel arguments, a `getty` or `login` on the same device, and a bootloader that offers an interruptible autoboot. The defect classes are specific. An interruptible autoboot with an unlocked environment lets the attacker change the kernel command line, which is enough for `init=/bin/sh` or for disabling a security module. A login prompt with a default or blank password is a finding on its own. A root shell with no login at all is the strongest case. A console that prints secrets — an API key at boot, a WiFi password, a device certificate — is a leak even when input is rejected. The 2025 relevant context is that most SoC vendors ship a production configuration that disables the console or removes the bootloader command set, so a device that ships with an interactive console is usually a build-configuration defect rather than a hardware limitation.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the console accepts input at the bootloader prompt **THEN** the branch is command-line control, and `init=/bin/sh` availability decides the severity.
2. **IF** the console presents a login **THEN** the branch is credential strength; check for default, blank, and shared passwords before anything else.
3. **IF** the console prints secrets at boot and rejects input **THEN** the finding is the leak, not the shell.
4. **IF** the interface is a different transport **THEN** start at [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md) for the classification.
5. **IF** secure boot verifies the kernel and the environment is locked **THEN** the console is a hardening note; say which guard is present.
6. **IF** the device has a physical case that requires destruction to reach the pads **THEN** record the access precondition; it changes the threat model, not the defect.
7. **IF** the console is log-only with no secrets **THEN** record `Verified Safe` with the boot log excerpt.

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

1. **Find the pads and the settings.** Three or four pads, one toggling at boot; a baud rate measured from the shortest pulse in a run of `U` bytes. Record both.
2. **Capture a full boot.** The boot log names the bootloader, the kernel command line, the mounted partitions, and often the services that start — which is most of the inventory you need.
3. **Choose the branch.** Interruptible autoboot, login prompt, no-auth shell, or secret printed at boot.
4. **Define the baseline-vs-probe differential.** Baseline: the boot log with no input sent, which shows the normal sequence. Probe: the same boot with a keystroke at the autoboot prompt. A prompt appearing in the probe and not the baseline is the finding.
5. **Name the stop condition.** Stop at the first interactive prompt that accepts a command, or the first secret visible in the log. Do not modify the device or change a password.
6. **State the proof.** Report the pads, the baud, the bootloader version, the prompt or the leaked value, and the guard that is absent. If the prompt rejects input and the log carries no secrets, record the negative with the excerpt.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `Hit any key to stop autoboot` and a `=>` prompt | An interruptible bootloader with a command interpreter, which is command-line control | U-Boot, barebox |
| `printenv bootargs` returning a writable variable | The kernel command line is attacker-controlled, so `init=/bin/sh` is reachable | Bootloader environment |
| A `login:` prompt on the console with `root` and no password | An authentication bypass at the physical boundary | BusyBox `getty`, `login` |
| `console=ttyS0,115200` in the boot log | The console is enabled in the kernel arguments, which is the precondition | Kernel command line |
| A boot log printing `wpa_passphrase=` or an API key | A secret leak that needs no shell at all | Init scripts, application startup |
| A bootloader with `CONFIG_CMD_ENV` removed and autoboot delay 0 | The console is present but not interruptible — the control | Bootloader build configuration |

## Worked Contrast

**Vulnerable: interruptible autoboot, writable bootargs, root shell with no password**

```text
U-Boot 2022.04 (Mar 02 2023 - 11:20:31 +0000)
DRAM:  512 MiB
Hit any key to stop autoboot:  0
=> printenv bootargs
bootargs=console=ttyS0,115200 root=/dev/mmcblk0p2 ro
=> setenv bootargs console=ttyS0,115200 root=/dev/mmcblk0p2 rw init=/bin/sh
=> boot
...
/ # id
uid=0(root) gid=0(root)
/ # cat /etc/shadow | head -2
root::19000:0:99999:7:::
```

**Hardened: autoboot not interruptible, environment locked, console log-only**

```text
U-Boot 2023.10 (Jan 15 2024 - 09:12:44 +0000)
DRAM:  512 MiB
Loading kernel from verified partition...
## Booting kernel from FIT image at 0x40080000 ...
   Verifying Hash Integrity ... sha256,rsa2048:prod-key+ OK
...
[    0.000000] Kernel command line: console=ttyS0,115200 root=/dev/dm-0 ro
[    1.204118] systemd[1]: Started Serial Getty on ttyS0.   # login required
```

```text
# The console requires authentication and prints no secrets:
buildroot login: root
Password:
Login incorrect
```

**Why this matters:** The left device boots to a root shell with an empty password because the bootloader let an attacker change the kernel command line, so physical access is full compromise with no exploit. The right device verifies a signed FIT image before boot, has a non-interruptible autoboot with a locked environment, requires a password on the serial getty, and prints no credentials in its boot log.

## When It Is NOT This Issue

- **A console that prints boot logs and ignores input.** Diagnostic output is not a compromise unless it carries a secret.
- **A login prompt with a strong, unique per-device password.** Authentication exists; the finding would be the password's distribution.
- **A bootloader prompt reachable only after a hardware modification that breaks tamper evidence.** The access precondition is part of the finding's severity.
- **A UART port on a development board rather than a production unit.** Confirm the SKU before filing.
- **A console on a device whose secure boot verifies the kernel and whose environment is locked.** The interface is present but yields only logs.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `hardware-debug-interfaces-uart-and-serial` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `hardware-debug-interfaces-uart-and-serial` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: hardware-debug-interfaces-uart-and-serial
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`hardware-debug-interfaces-jtag-and-swd`](../hardware-debug-interfaces-jtag-and-swd/SKILL.md) - Mobile, Hardware, Wireless and ICS (leaf)
- [`android-app-security`](../android-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`ios-app-security`](../ios-app-security/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)
- [`mobile-instrumentation-and-pinning-bypass`](../mobile-instrumentation-and-pinning-bypass/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `hardware-debug-interfaces-uart-and-serial` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 5 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/awesome_list (3), CYBER_CPT/ctf_search (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
