---
name: firmware-extraction-and-emulation
description: "Extracts and emulates firmware: image carving, filesystem recovery, architecture identification and full-system emulation for dynamic testing. Use when analysing an embedded device firmware."
family: mobile-hardware-wireless-ics
tier: core
triggers: ["firmware extraction", "firmware emulation", "binwalk", "squashfs", "qemu firmware"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-116]
related: [android-app-security, ios-app-security, mobile-instrumentation-and-pinning-bypass, hardware-debug-interfaces]
---

# Firmware Extraction and Emulation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Mobile, Hardware, Wireless and ICS`](../README.md) | Tier: **core** | Paired Counterpart: [`ics-and-ot-passive-network-monitoring`](../../../blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md)

## Mechanism and Preconditions

Firmware review starts with extraction and the extraction determines what analysis is possible. A vendor image is usually a container of containers: a header with a checksum and a compression type, then a bootloader, a kernel, and one or more filesystems, each possibly compressed or encrypted. `binwalk` identifies the signatures and extracts the layers; the filesystem type decides the next tool — SquashFS needs `unsquashfs`, JFFS2 or UBIFS needs the MTD tools, a CramFS needs `cramfsck`, and an encrypted filesystem needs the key from the bootloader or the SoC. Emulation is the second half: `qemu-system-arm` or `qemu-system-mips` with a kernel and a rootfs can boot the vendor firmware far enough to observe init scripts, and `firmadyne`-style harnesses automate the network setup that most images assume. The review question is what the extracted content allows you to conclude — hardcoded credentials, a disabled service, an update path without signature verification — and each conclusion needs a file and an offset. A firmware finding without a locator cannot be reproduced by the vendor, which makes it unusable.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the image has a header with a checksum and a compression flag **THEN** identify the container format before extracting; a wrong offset produces garbage that looks like encryption.
2. **IF** the extraction yields a SquashFS or CramFS **THEN** the root filesystem is readable and the review moves to init scripts and credentials.
3. **IF** the extraction yields high entropy with no signature **THEN** the layer is encrypted or compressed with an unknown algorithm; look for the key in the bootloader before concluding.
4. **IF** emulation boots to a shell **THEN** the branch is runtime observation, and the init sequence is the artefact.
5. **IF** the finding is a debug interface rather than content **THEN** start at [`hardware-debug-interfaces`](../hardware-debug-interfaces/SKILL.md).
6. **IF** the finding is the update path rather than the image **THEN** start at [`secure-boot-and-trusted-execution`](../secure-boot-and-trusted-execution/SKILL.md).
7. **IF** every layer extracts and the filesystem contains no credentials and no unsigned update path **THEN** record `Verified Safe` with the layer inventory and the files checked.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fingerprint the image.** Size, entropy per megabyte, and the signatures `binwalk` recognises. A flat entropy profile suggests encryption or a single compressed stream; a stepped profile suggests a container.
2. **Extract layer by layer, recording offsets.** Each extraction step's offset is part of the evidence chain, and a re-extraction from the same offset must produce the same content.
3. **Mount or unpack the filesystem read-only.** Never mount read-write, and never modify the extracted tree — the extraction is the evidence.
4. **Choose the branch.** Credential in a file, service configured insecurely, update path without verification, or a private key in the image.
5. **Define the baseline-vs-probe differential.** Baseline: the extracted tree as it ships. Probe: the same path in the vendor's documented default configuration, or a later version. A credential present in both is a design decision; one added in this version is a regression.
6. **Name the stop condition.** Stop when each finding has a file path and an offset within the image. Do not execute untrusted binaries on a host; emulation is the only execution path.
7. **State the proof.** Report the layer offsets, the filesystem type, the file path, and the content class. If the image is encrypted beyond recovery, record that with the entropy evidence and what would be needed to proceed.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `DECIMAL  HEXADECIMAL  DESCRIPTION` with `Squashfs filesystem` | A readable root filesystem, which is the entry point for all content review | `binwalk` output |
| A `U-Boot` or `FIT` header at an offset | A bootloader that may carry the kernel command line and the console configuration | Extracted bootloader |
| `/etc/shadow` with a hash for `root` | A credential at rest, and the hash type decides the cracking cost | Extracted rootfs |
| `-----BEGIN RSA PRIVATE KEY-----` in `/etc/` | A private key shipped in the image, which every device shares | Extracted rootfs |
| An entropy profile flat at 7.9 bits/byte | Encrypted or compressed with an unknown algorithm, so extraction stops | `binwalk -E` output |
| A `postinst` or init script starting `telnetd` | A service that is on by default, which is the exposure | Extracted init scripts |

## Worked Contrast

**Vulnerable: image with a readable rootfs containing a shared key and a debug service**

```text
$ binwalk -e firmware_v2.1.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             uImage header, header size: 64 bytes
64            0x40            LZMA compressed data
4126720       0x3F0000        Squashfs filesystem, little endian, version 4.0

$ unsquashfs -d rootfs squashfs-root/0x3F0000.squashfs >/dev/null
$ cat rootfs/etc/shadow | head -2
root:$1$abcd1234$Fq2Zk9...:19000:0:99999:7:::
$ rg -n "BEGIN RSA PRIVATE KEY" rootfs/etc/
rootfs/etc/ssl/private/device.key:1:-----BEGIN RSA PRIVATE KEY-----
$ rg -n "telnetd" rootfs/etc/init.d/
rootfs/etc/init.d/rcS:14:telnetd -l /bin/sh &
```

**Hardened: image whose rootfs carries no shared secrets and no debug service**

```text
$ binwalk -e firmware_v2.2.bin
0             0x0             uImage header, header size: 64 bytes
64            0x40            LZMA compressed data
4126720       0x3F0000        Squashfs filesystem, little endian, version 4.0

$ unsquashfs -d rootfs squashfs-root/0x3F0000.squashfs >/dev/null
$ cat rootfs/etc/shadow
root:*:19000:0:99999:7:::            # locked; no shared password
$ rg -n "PRIVATE KEY" rootfs/etc/ || echo "no private key in the image"
no private key in the image
$ rg -n "telnetd|dropbear|sshd" rootfs/etc/init.d/ || echo "no remote shell enabled by default"
no remote shell enabled by default
```

**Why this matters:** The left image ships a shared root password hash, a private key common to every device of that model, and a telnet daemon bound to a shell — three findings that each need only the extracted file path. The right image has the root account locked, no key material in the filesystem, and no remote shell started by default, so the same extraction yields no credential finding.

## When It Is NOT This Issue

- **An encrypted filesystem whose key is in the SoC.** The extraction stops, which is the control; the finding would be the key's custody.
- **A `root` hash of `*` or `!`** in `/etc/shadow`. The account is locked, not a weak credential.
- **A public key or certificate in the image.** Public by definition.
- **A telnet binary present but not started by any init script.** The presence is not the exposure; the init line is.
- **A filesystem that extracts with wrong ownership because it was mounted on a different host.** An artefact of extraction, not a defect.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `firmware-extraction-and-emulation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `firmware-extraction-and-emulation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: firmware-extraction-and-emulation
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
- [`wireless-wifi-and-bluetooth-attacks`](../wireless-wifi-and-bluetooth-attacks/SKILL.md) - Mobile, Hardware, Wireless and ICS (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `firmware-extraction-and-emulation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (8), CYBER_CPT/ctftime (5), CYBER_CPT/ctf_wiki (5), CYBER_CPT/awesome_list (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
