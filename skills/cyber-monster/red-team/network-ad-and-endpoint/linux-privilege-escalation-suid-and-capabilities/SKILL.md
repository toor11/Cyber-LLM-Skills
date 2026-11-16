---
name: linux-privilege-escalation-suid-and-capabilities
description: SUID binaries and Linux capabilities. Covers SUID and SGID binary abuse, shared object hijacking, and capability-based escalation through cap_setuid and cap_dac_read_search. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["suid", "setuid escalation", "linux capabilities", "getcap", "cap_setuid"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [linux-privilege-escalation, linux-privilege-escalation-sudo-abuse, linux-privilege-escalation-cron-and-systemd, linux-privilege-escalation-nfs-and-share-abuse]
parent: linux-privilege-escalation
---

# Linux Privilege Escalation Suid and Capabilities - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md)

## Mechanism and Preconditions

A setuid binary runs with its owner's effective UID, and a file capability grants a subset of root's privileges to an otherwise unprivileged binary. Both are legitimate mechanisms used by `passwd`, `ping` and `mount`, and both become findings only when the binary consumes an input the invoking user can influence: a library path, a configuration file, a plugin directory, a `PATH` entry, or an environment variable that the binary honours. The methodology is therefore mode-and-capability enumeration plus an input-influence check for each result.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the setuid binary is on the distribution's documented list **THEN** it is expected; check whether its configuration or library path is writable before concluding anything
3. **IF** a file capability grants `cap_setuid` or `cap_setgid` **THEN** the binary can change identity outright, which is sufficient for a full shell
4. **IF** the binary loads a library from a relative path **THEN** `RPATH` of `.` or an empty `DT_RUNPATH` is the classic condition
5. **IF** the binary honours an environment variable such as `LD_PRELOAD` **THEN** modern glibc strips it for setuid binaries, so check the actual dynamic loader behaviour before reporting
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `linux-privilege-escalation-suid-and-capabilities` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A sudo rule is the artefact | [`linux-privilege-escalation-sudo-abuse`](../linux-privilege-escalation-sudo-abuse/SKILL.md) | Delegated commands rather than mode bits |
| A scheduled job is the artefact | [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) | Timed execution |
| The kernel is the boundary | [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) | Kernel primitives |
| A container grants the capability | [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) | Namespace and capability inheritance |
| Need the class-level branch table first | [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Build the inventory and compare it against the package database.** `find -perm -4000` plus `getcap -r /` gives the list; `rpm -V` or `dpkg -V` tells you which files are unmodified package content. Anything not accounted for by a package is the interesting subset.
2. **Check the file's own integrity and ownership.** A setuid binary owned by a non-root user, or one whose mode differs from the package manifest, is a finding on its own. File integrity tooling records exactly this, which makes the check cheap and the evidence strong.
3. **Look for an input the invoking user can influence.** Library search path from `readelf -d`, configuration file ownership and mode, plugin directories, and any `PATH` lookup inside the binary's behaviour. The differential is a writable target the binary reads while running with elevated privilege.
4. **Baseline against a hardened build.** A hardened host has a documented setuid list and no writable libraries or configs consumed by those binaries. Deviation is the finding, and the remediation is either removing the bit or fixing the writable input.
5. **State the proof and the stop condition.** Proof is the mode or capability plus the writable input: `-rwsr-xr-x` on a binary whose `DT_RPATH` includes a user-writable directory, or `cap_dac_read_search+ep` on a binary that reads an arbitrary path. Stop at the first pair; escalating is a separate step.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Setuid bit on an unmodified package binary | Proves the expected state, where the question becomes whether an input is writable; any Linux host. |
| `cap_setuid+ep` on a user-writable binary | Proves immediate identity change to any UID, since the capability is exactly what a shell needs; any Linux host with capabilities. |
| `DT_RPATH` containing a writable directory | Proves a library can be loaded into the privileged process; any Linux host with an ELF binary built with a relative rpath. |
| Setuid binary consuming a config file owned by a non-root user | Proves the binary's behaviour can be redirected by that user; any Linux host. |
| Capability `cap_dac_read_search` | Proves arbitrary file read regardless of DACL, which reaches `/etc/shadow`; any Linux host. |

## Worked Contrast

**Weak configuration — a setuid helper reading a configuration file writable by its own group:**

```bash
ls -l /usr/local/bin/backupctl /etc/backupctl.conf
# -rwsr-xr-x root root  /usr/local/bin/backupctl
# -rw-rw-r-- root backup /etc/backupctl.conf   (the invoking user is in 'backup')
# the config names a program to run, executed with root's effective UID
```

**Hardened configuration — config made root-owned read-only and the setuid bit removed where unnecessary:**

```bash
chown root:root /etc/backupctl.conf
chmod 0644 /etc/backupctl.conf
chmod u-s /usr/local/bin/backupctl
# and grant the operation through sudo with an argument-checking wrapper instead
# verification: ls shows no setuid bit and the config is not writable by the group
```

**Why this matters:** the boundary is the effective UID combined with a user-influenced input, so the control is either the mode or the input permission, and the verification is reading both back.

## When It Is NOT This Issue

- **`passwd`, `mount`, `su`, `ping` and `chsh`.** These are setuid by design on most distributions; their presence is not a finding and their configuration is usually root-owned.
- **`LD_PRELOAD` against a setuid binary.** Modern glibc ignores it for setuid executables; reporting it as an escalation path without checking the loader is a false positive.
- **A world-writable directory that no privileged binary consults.** `/tmp` is writable by design; the finding requires a privileged binary to read a path the user controls inside it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `linux-privilege-escalation-suid-and-capabilities` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `linux-privilege-escalation-suid-and-capabilities` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: linux-privilege-escalation-suid-and-capabilities
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1068]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) - Blue Detection/Defense Counterpart
- [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) - Network, Active Directory and Endpoint (flagship)
- [`linux-privilege-escalation-sudo-abuse`](../linux-privilege-escalation-sudo-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-nfs-and-share-abuse`](../linux-privilege-escalation-nfs-and-share-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `linux-privilege-escalation-suid-and-capabilities` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/oxdf (6), OffsecCyber (1), CYBER_CPT/L5/ctf_search (1), CYBER_CPT/peiqi_wiki (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
