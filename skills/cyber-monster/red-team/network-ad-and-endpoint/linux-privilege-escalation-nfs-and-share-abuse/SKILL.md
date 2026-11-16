---
name: linux-privilege-escalation-nfs-and-share-abuse
description: NFS and share permission abuse. Covers no_root_squash NFS mounts, writable exports and group-writable shared paths to place SUID binaries or steal credentials. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["nfs no_root_squash", "nfs escalation", "writable export", "share abuse linux"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [linux-privilege-escalation, linux-privilege-escalation-sudo-abuse, linux-privilege-escalation-suid-and-capabilities, linux-privilege-escalation-cron-and-systemd]
parent: linux-privilege-escalation
---

# Linux Privilege Escalation Nfs and Share Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md)

## Mechanism and Preconditions

NFS trusts the client to assert a UID, so an export with `no_root_squash` lets a root user on a client create files owned by root on the server, including setuid binaries. Even with `root_squash`, a writable export mounted by a host the assessor controls allows file creation as the squashed identity, which can be enough where a scheduled job or a login path consumes the file. The methodology is export enumeration, then a check of whether the export is writable and how it handles ownership.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the export is `no_root_squash` and writable **THEN** root-owned file creation on the server is the finding, and a setuid binary in a privileged path completes it
3. **IF** the export is `root_squash` but writable by an unprivileged identity **THEN** file content can still be changed, which matters if a privileged job consumes it
4. **IF** the export is read-only **THEN** no write path exists; the finding would be data disclosure, which is a different claim
5. **IF** the share is SMB rather than NFS **THEN** ownership mapping differs entirely; treat it as a SMB share rather than an NFS export
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `linux-privilege-escalation-nfs-and-share-abuse` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A scheduled job consumes the writable path | [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) | Timed execution of the modified file |
| The share is mounted by a user session | [`linux-lateral-movement`](../linux-lateral-movement/SKILL.md) | Cross-host access rather than escalation |
| The export is on a NAS with its own identity model | [`service-enumeration`](../service-enumeration/SKILL.md) | Protocol-level enumeration |
| The client is a container | [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) | Namespace and mount boundaries |
| Need the class-level branch table first | [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate exports and their options from an authorised client.** `showmount -e` lists the exports; the options (`rw`, `no_root_squash`, `all_squash`, `sec=`) come from the server's export table, which you may need the client's mount to reveal. The option set, not the path, is what decides the technique.
2. **Map the ownership behaviour before writing anything.** Create a test file as an unprivileged user and inspect its owner on the server. `root_squash` maps root to `nobody`, `no_root_squash` preserves root, and `all_squash` maps everything — the observed mapping is the evidence.
3. **Check whether a privileged consumer exists.** A writable export is only an escalation where a root process reads or executes from it: a cron job, a login script, a service unit, or a `PATH` entry. Without a consumer it is a data-integrity finding, which is a different severity.
4. **Baseline against a hardened export configuration.** `root_squash` and `all_squash` where possible, exports restricted by host and network, and `sec=krb5` or `sec=krb5p` where Kerberos is available. Deviation is the finding.
5. **State the proof and stop.** Proof is the export option set plus the observed file ownership from an authorised client. Creating a setuid binary and executing it on the server is a separate step and is not required to report the exposure.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `no_root_squash` in the export options | Proves root-owned file creation on the server from a client, which reaches setuid and privileged paths; any NFS server. |
| Writable export with `root_squash` | Proves content modification as `nobody`, which matters where a job consumes the file; any NFS server. |
| `sec=sys` on an export reachable from a user subnet | Proves UID assertion is unauthenticated, the root of the trust problem; any NFS server without Kerberos. |
| Export restricted by hostname only | Proves DNS or `/etc/hosts` manipulation can grant access, since the check is name-based; any NFS server. |
| Shared home directory across hosts | Proves one host's compromise reaches the others' dotfiles, including `authorized_keys`; any NFS-mounted home. |

## Worked Contrast

**Weak configuration — a writable export with root squash disabled, reachable from a user subnet:**

```bash
# /etc/exports on the server
/srv/app 10.20.30.0/24(rw,no_root_squash,no_subtree_check)
# a root user on any client in that range creates root-owned files on the server,
# including a setuid binary in a directory the server executes
```

**Hardened configuration — root squash enabled, export scoped to the application hosts:**

```bash
# /etc/exports
/srv/app 10.20.40.11(rw,root_squash,all_squash,no_subtree_check)
exportfs -ra
# verification: a test file created as root on the client is owned by nobody on the server
```

**Why this matters:** the trust is the UID assertion, so the control is the squash option and the host scope, and the verification is the observed ownership of a newly created file.

## When It Is NOT This Issue

- **A read-only export.** No write path exists; reporting it as an escalation overstates the finding.
- **`no_root_squash` scoped to a single backup host.** A documented backup relationship may require it; check the host list and the backup tool's account before reporting.
- **A shared home directory mounted read-only on application servers.** The write path exists only on the host where it is mounted read-write; check the mount options per client.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `linux-privilege-escalation-nfs-and-share-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `linux-privilege-escalation-nfs-and-share-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: linux-privilege-escalation-nfs-and-share-abuse
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
- [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `linux-privilege-escalation-nfs-and-share-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/oxdf (3), CYBER_CPT/hacktricks (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
