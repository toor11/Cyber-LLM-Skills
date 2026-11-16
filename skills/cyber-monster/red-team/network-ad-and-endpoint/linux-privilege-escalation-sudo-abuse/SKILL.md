---
name: linux-privilege-escalation-sudo-abuse
description: Linux sudo misconfiguration abuse. Covers sudo rules granting dangerous binaries, LD_PRELOAD and env_keep abuse, sudoedit exploitation and GTFOBins mapping. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["sudo abuse", "sudo -l", "sudoedit", "ld_preload sudo", "sudo misconfiguration"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [linux-privilege-escalation, linux-privilege-escalation-suid-and-capabilities, linux-privilege-escalation-cron-and-systemd, linux-privilege-escalation-nfs-and-share-abuse]
parent: linux-privilege-escalation
---

# Linux Privilege Escalation Sudo Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md)

## Mechanism and Preconditions

A sudo rule grants permission to run a specific command as another user, and sudo's enforcement is command-path based rather than argument based. If the permitted command can execute arbitrary input — an editor, a pager, a language interpreter, a file copier with a destination of the attacker's choosing — the rule is equivalent to the privilege it delegates. The methodology therefore reads `sudo -l` line by line and asks what each permitted binary can be made to do with its documented options.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the rule names an editor, pager or interpreter **THEN** the rule is effectively unrestricted; document it as such rather than testing every escape
3. **IF** the rule names a specific subcommand **THEN** check whether the subcommand itself has a documented option that writes or executes a file
4. **IF** the rule permits `env_keep` with a dangerous variable **THEN** that variable can load code into the permitted process; check `LD_PRELOAD` and `PYTHONPATH` handling
5. **IF** the rule requires a password and none is known **THEN** this branch does not apply unless the password is already held
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `linux-privilege-escalation-sudo-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The artefact is a setuid binary | [`linux-privilege-escalation-suid-and-capabilities`](../linux-privilege-escalation-suid-and-capabilities/SKILL.md) | Mode bits rather than a rule |
| The artefact is a scheduled job | [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) | Timed execution as root |
| The boundary is the kernel | [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) | Kernel primitives |
| The boundary is a remote filesystem | [`linux-privilege-escalation-nfs-and-share-abuse`](../linux-privilege-escalation-nfs-and-share-abuse/SKILL.md) | Export trust |
| Need the class-level branch table first | [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the complete rule set, including defaults and includes.** `sudo -l` shows the effective rules; `sudo -ll` shows the long form with the `Defaults` and `env_keep` that apply. A rule that looks safe can be defeated by an inherited environment variable, so the defaults are part of the analysis.
2. **Classify each permitted binary by its documented capabilities.** An editor or pager can spawn a shell. An interpreter runs any script. A copier can write anywhere. A service-control binary can restart a unit from a writable path. The classification is what turns a rule list into findings.
3. **Check argument handling for each rule.** A rule that names a subcommand with fixed arguments is narrow; a rule that permits a wildcard or an arbitrary argument is not. Read the sudoers line as written, because the wildcard is where the intent usually breaks.
4. **Baseline against a rule set that uses wrappers.** A hardened host delegates through small wrapper scripts that validate arguments and are owned by root with mode 0750. Deviation — a direct interpreter grant — is the finding.
5. **State the proof and stop.** Proof is the `sudo -l` line plus the documented capability that makes it unrestricted. Running the escape to obtain a root shell is a separate authorised step and is not needed to report the rule.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `NOPASSWD: /usr/bin/vim` | Proves unrestricted command execution as the target user, since vim can invoke a shell; any Linux host with sudo. |
| `(ALL) /usr/bin/find` without argument restriction | Proves arbitrary command execution through `-exec`, a documented find capability; any Linux host. |
| `env_keep += LD_PRELOAD` | Proves a library can be injected into the permitted binary, which executes code as the target user; any Linux host with that default. |
| Wildcard argument in a sudoers rule | Proves argument injection past the path check, since `--` and path traversal defeat naive wildcards; any Linux host. |
| `(root) NOPASSWD: /usr/bin/systemctl restart app` | Proves a restart of a unit whose file may be writable, which is a two-step escalation; any Linux host with systemd. |

## Worked Contrast

**Weak configuration — a sudoers rule granting a pager and preserving a loader variable:**

```bash
# /etc/sudoers.d/readlogs
Defaults:logreader env_keep += LD_PRELOAD
logreader ALL=(root) NOPASSWD: /usr/bin/less /var/log/*
# less can run shell commands, and LD_PRELOAD injects a library into it
```

**Hardened configuration — a wrapper that validates the path and clears the environment:**

```bash
# replace with a root-owned wrapper that reads a fixed path and clears the environment
printf '#!/bin/sh\ncase "$1" in /var/log/app.log) exec /usr/bin/cat -- "$1";; *) exit 1;; esac\n' \
  > /usr/local/sbin/readlog
chown root:root /usr/local/sbin/readlog; chmod 0750 /usr/local/sbin/readlog
# and remove env_keep for LD_PRELOAD
# verification: sudo -ll shows only the wrapper and no env_keep entry
```

**Why this matters:** the exposure is the combination of an unrestricted binary and a preserved loader variable, so both must go; the verification is the effective rule listing rather than a shell.

## When It Is NOT This Issue

- **A rule naming a specific subcommand with fixed arguments.** `systemctl status app` cannot execute arbitrary code; only rules with argument latitude are findings.
- **A rule that requires a password the user must supply.** The rule is still a delegation but the precondition is the password; state it.
- **`sudo -l` output for a user in `wheel` with `ALL=(ALL) ALL`.** That is administrative access by design; the finding would be that the account should not be in the group.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `linux-privilege-escalation-sudo-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `linux-privilege-escalation-sudo-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: linux-privilege-escalation-sudo-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1068]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) - Blue Detection/Defense Counterpart
- [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) - Network, Active Directory and Endpoint (flagship)
- [`linux-privilege-escalation-suid-and-capabilities`](../linux-privilege-escalation-suid-and-capabilities/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-nfs-and-share-abuse`](../linux-privilege-escalation-nfs-and-share-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `linux-privilege-escalation-sudo-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/oxdf (6), CYBER_CPT/ctftime (2), CYBER_CPT/ctf_wiki (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 8 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
