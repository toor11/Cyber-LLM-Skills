---
name: linux-privilege-escalation
description: "Escalates from a low-privileged Linux session to root: SUID binaries, sudo misconfiguration, cron jobs, capabilities, NFS root squash, writable paths and kernel exploits. Use on any Linux foothold."
family: network-ad-and-endpoint
tier: flagship
triggers: ["linux privesc", "linux privilege escalation", "linpeas", "sudo abuse", "suid", "gtfobins"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [linux-privilege-escalation-sudo-abuse, linux-privilege-escalation-suid-and-capabilities, linux-privilege-escalation-cron-and-systemd, network-recon-and-port-scanning]
---

# Linux Privilege Escalation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **flagship** | Paired Counterpart: [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md)

## Mechanism and Preconditions

Linux privilege escalation is decided by configuration artefacts rather than by a single kernel bug: a setuid binary whose behaviour can be redirected, a sudo rule that permits an interpreter, a cron job in a directory a non-root user can write, a service unit that loads a file from a relative path, or a capability that grants a narrow but sufficient privilege. Each artefact is readable before exploitation, so the methodology is enumeration of the artefacts plus a check of whether the current user can influence any input they consume.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** `sudo -l` shows a permitted command **THEN** use [`linux-privilege-escalation-sudo-abuse`](../linux-privilege-escalation-sudo-abuse/SKILL.md) for rule-by-rule analysis
2. **IF** a setuid binary or a file capability is present **THEN** use [`linux-privilege-escalation-suid-and-capabilities`](../linux-privilege-escalation-suid-and-capabilities/SKILL.md)
3. **IF** a cron job, timer or service unit is writable **THEN** use [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md)
4. **IF** the kernel version is old or a container runtime is exposed **THEN** use [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md)
5. **IF** an NFS export or a shared home directory is reachable **THEN** use [`linux-privilege-escalation-nfs-and-share-abuse`](../linux-privilege-escalation-nfs-and-share-abuse/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `linux-privilege-escalation` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A sudo rule permits an interpreter | [`linux-privilege-escalation-sudo-abuse`](../linux-privilege-escalation-sudo-abuse/SKILL.md) | GTFOBins-style rule analysis |
| A setuid binary or capability is present | [`linux-privilege-escalation-suid-and-capabilities`](../linux-privilege-escalation-suid-and-capabilities/SKILL.md) | File mode and effective capability |
| A scheduled job or unit is writable | [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) | Execution as another identity on a timer |
| Kernel or container boundary | [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) | Namespace and kernel primitives |
| NFS, home directories or shares | [`linux-privilege-escalation-nfs-and-share-abuse`](../linux-privilege-escalation-nfs-and-share-abuse/SKILL.md) | Remote filesystem trust |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix the identity and group baseline.** `id`, the supplementary groups, and whether the account has passwordless sudo. A finding that does not name the starting identity cannot be reproduced, and group membership often supplies the write access that makes an artefact exploitable.
2. **Enumerate artefacts by class, not by tool output.** Setuid and setgid files, file capabilities, sudo rules, writable directories in `PATH`, cron and systemd timers, world-writable service units, and readable credential files. Each class has a distinct precondition, so mixing them into one list obscures which one is actionable.
3. **Check whether the current user can influence an input.** A setuid binary that only reads a fixed configuration is not exploitable; the same binary reading a file in a user-writable directory is. The differential is the file's owner and mode versus the binary's effective UID.
4. **Baseline against a CIS-hardened build of the same distribution.** A hardened host has a documented setuid list, no world-writable directories in root's `PATH`, and no sudo rules granting interpreters. Deviation is the finding, and each deviation is directly remediable.
5. **State the proof and the stop condition.** Proof is the artefact plus the write or input condition: the setuid bit with a writable library path, the sudo rule naming `vim` or `less`, the cron file writable by the current user. Stop at the first artefact that satisfies both; a shell as root is a separate authorised step.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `sudo -l` listing an interpreter | Proves a command-level rule that can spawn a shell, since the permitted binary executes arbitrary input; any Linux host with sudo. |
| Setuid bit with a writable library or config | Proves an effective-UID change can be steered by a non-root user; any Linux host. |
| File capability `cap_setuid+ep` | Proves a narrow privilege that is sufficient for a full shell; any Linux host with capabilities. |
| Cron file writable by a non-root user | Proves execution as the cron owner, usually root, on a schedule; any Linux host. |
| `PATH` entry writable by the current user on a root-executed script | Proves command resolution can be redirected, a classic cron and service-unit flaw; any Linux host. |

## Worked Contrast

**Weak configuration — a sudo rule permitting an interpreter with no argument restriction:**

```bash
# /etc/sudoers.d/ops
%ops ALL=(ALL) NOPASSWD: /usr/bin/vim
# vim can execute shell commands, so the rule is equivalent to full root access
sudo -l
```

**Hardened configuration — rules scoped to subcommands and a wrapper that validates arguments:**

```bash
# replace the interpreter grant with a wrapper that accepts a fixed subcommand only
# %ops ALL=(root) NOPASSWD: /usr/local/sbin/ops-restart
install -o root -g root -m 0750 /dev/null /usr/local/sbin/ops-restart
# verification: sudo -l shows the wrapper only, and vim is no longer permitted
```

**Why this matters:** the exposure is the permission to run an interpreter, so the control is the sudoers rule and the verification is `sudo -l` output rather than a test of the resulting shell.

## When It Is NOT This Issue

- **A setuid binary that only reads fixed configuration.** `passwd`, `mount` and `ping` are setuid by design and do not accept a user-controlled library path; their presence is not a finding.
- **A world-writable directory outside every privileged `PATH`.** `/tmp` and `/var/tmp` are writable by design; only directories that appear in a root-executed search path matter.
- **A kernel version with a CVE that the distribution backported.** Distribution kernels carry backports without changing the version string; check the package changelog before naming a CVE.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `linux-privilege-escalation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `linux-privilege-escalation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: linux-privilege-escalation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1068]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) - Blue Detection/Defense Counterpart
- [`linux-privilege-escalation-sudo-abuse`](../linux-privilege-escalation-sudo-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-suid-and-capabilities`](../linux-privilege-escalation-suid-and-capabilities/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `linux-privilege-escalation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 30 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/oxdf (13), CYBER_CPT/L5/ctf_search (10), OffsecCyber (4), hackerone_disclosed_reports (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
