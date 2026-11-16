---
name: linux-privilege-escalation-cron-and-systemd
description: Cron and systemd abuse. Covers writable cron scripts, PATH abuse in cron, systemd unit and timer permissions, and environment injection into scheduled jobs. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["cron abuse", "writable cron", "systemd unit abuse", "timer escalation"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [linux-privilege-escalation, linux-privilege-escalation-sudo-abuse, linux-privilege-escalation-suid-and-capabilities, linux-privilege-escalation-nfs-and-share-abuse]
parent: linux-privilege-escalation
---

# Linux Privilege Escalation Cron and Systemd - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md)

## Mechanism and Preconditions

Cron and systemd timers run jobs as a configured user, usually root, from configuration that is often written by a deployment tool with permissive ownership. Three conditions produce escalation: the job file itself is writable by a non-root user, a directory or script the job executes is writable, or the job resolves a command through `PATH` that includes a writable directory. Systemd adds a fourth: a unit file in a location that a non-root user can write, which systemd will load on the next daemon-reload.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** a cron file or drop-in is writable **THEN** the job runs as its owner on a schedule, so the write is the finding
3. **IF** a script invoked by a job is writable **THEN** same effect, and often easier to miss because the cron line itself looks correct
4. **IF** the job uses a relative command name **THEN** `PATH` resolution applies; check the `PATH` set at the top of the crontab or in the unit's environment
5. **IF** a systemd unit file is writable **THEN** `systemctl daemon-reload` plus a restart applies the change, so the finding includes the restart trigger
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `linux-privilege-escalation-cron-and-systemd` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A sudo rule is the artefact | [`linux-privilege-escalation-sudo-abuse`](../linux-privilege-escalation-sudo-abuse/SKILL.md) | Delegated command execution |
| A setuid binary is the artefact | [`linux-privilege-escalation-suid-and-capabilities`](../linux-privilege-escalation-suid-and-capabilities/SKILL.md) | Mode-bit escalation |
| The job is used for persistence rather than escalation | [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) | Durability and triggers |
| The job runs inside a container | [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) | Namespace boundaries |
| Need the class-level branch table first | [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate every scheduling mechanism, not just cron.** System crontabs, user crontabs, `cron.d` and `cron.daily` drop-ins, systemd timers with their service units, and `at` jobs. Each has a different path and a different ownership model, so a cron-only review misses the majority of modern scheduling.
2. **Read ownership and mode on the job and on everything it executes.** The job file, the script it names, and any file the script sources. The writable element is what matters; a root-owned job calling a user-writable script is the same finding as a writable job.
3. **Check the execution environment the job inherits.** The `PATH` in the crontab header or the unit's `Environment=`, plus any `.` entry. A relative command name with a writable `PATH` entry is a resolution flaw independent of file ownership.
4. **Baseline against a configuration-managed host.** Job files owned by root with mode 0644 or 0640, scripts under `/usr/local/sbin` owned by root, and explicit absolute paths. Deviation on any of the three is the finding.
5. **State the proof and stop.** Proof is the writable file or directory plus the scheduling entry that executes it as a privileged user, read from the live filesystem. Waiting for the job to fire is a state change and is not required.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Cron file writable by a non-root user | Proves execution as the cron owner, usually root, at the next schedule tick; any Linux host. |
| Script invoked by a root cron job with a write ACE | Proves the same effect through the script rather than the job file; any Linux host. |
| Relative command name with a writable `PATH` entry | Proves command resolution can be redirected for a privileged job; any Linux host. |
| Systemd unit file in `/etc/systemd/system` writable by a non-root user | Proves a unit can be replaced and loaded, which is persistent execution as the unit's user; any systemd host. |
| Timer unit whose `OnCalendar` is frequent | Proves the delay before a modified job takes effect, which sets the urgency of the finding; any systemd host. |

## Worked Contrast

**Weak configuration — a root cron job executing a script in a user-writable deployment directory:**

```bash
# /etc/cron.d/app-maintenance
*/5 * * * * root /opt/app/deploy/nightly.sh
ls -ld /opt/app/deploy
# drwxrwxr-x app app  -> the 'app' service account, and every user in that group, can edit nightly.sh
```

**Hardened configuration — job executes a root-owned script with an explicit path:**

```bash
install -o root -g root -m 0750 /opt/app/deploy/nightly.sh /usr/local/sbin/app-nightly.sh
sed -i 's#/opt/app/deploy/nightly.sh#/usr/local/sbin/app-nightly.sh#' /etc/cron.d/app-maintenance
# verification: ls shows root ownership and no group write, and the cron line names the new path
```

**Why this matters:** the privilege comes from the schedule owner, so the control is the ownership of everything the job executes and the verification is the file mode plus the job line.

## When It Is NOT This Issue

- **A writable file outside any scheduled job's execution path.** Only files a privileged job reads or executes matter; a writable README in the same directory is not a finding.
- **A user crontab owned by its own user.** A user's own crontab runs as that user, so writability is expected and grants nothing.
- **A systemd unit in `/etc/systemd/user` for the same user.** User units run in the user's own manager; they are not a privilege boundary.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `linux-privilege-escalation-cron-and-systemd` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `linux-privilege-escalation-cron-and-systemd` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: linux-privilege-escalation-cron-and-systemd
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
- [`linux-privilege-escalation-suid-and-capabilities`](../linux-privilege-escalation-suid-and-capabilities/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-nfs-and-share-abuse`](../linux-privilege-escalation-nfs-and-share-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `linux-privilege-escalation-cron-and-systemd` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/atomic_red_team (1), CYBER_CPT/mitre_attack_enterprise (1), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
