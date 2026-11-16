---
name: linux-lateral-movement
description: "Moves laterally on Linux: SSH key reuse, agent forwarding abuse, shared NFS and home directories, Ansible and config management credentials, and container host escapes from within. Use after a Linux foothold in a multi-host environment."
family: network-ad-and-endpoint
tier: leaf
triggers: ["linux lateral movement", "ssh pivot", "nfs lateral", "ansible credential", "agent forwarding"]
cwe: [CWE-269]
owasp: []
attack: [T1021]
capec: [CAPEC-122]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# Linux Lateral Movement - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Lateral movement on Linux rarely uses an exploit. It uses the estate's own automation: SSH keys in `authorized_keys` files that were distributed by a configuration tool, agent forwarding that exposes a socket on every host the first hop touches, shared home directories and NFS exports mounted from a central filer, credentials stored in Ansible Vault files or CI variables, and container sockets that control the host. The methodology is therefore credential reachability: which key or secret grants which host, and what the trust relationship between hosts actually is.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an SSH private key is readable **THEN** check the corresponding `authorized_keys` on candidate hosts before assuming reuse; keys are often scoped by `from=` or a forced command
2. **IF** an SSH agent socket is present **THEN** agent forwarding lets the key be used without reading it, but only while the parent session lives; check `SSH_AUTH_SOCK`
3. **IF** a shared NFS home directory is mounted **THEN** the dotfiles of every account on the filer are reachable, including `authorized_keys` and history files
4. **IF** a container runtime socket is mounted **THEN** that is container-host control, which is a stronger finding than a lateral hop; see [`linux-privilege-escalation-kernel-and-container-escapes`](../linux-privilege-escalation-kernel-and-container-escapes/SKILL.md)
5. **IF** automation credentials are readable **THEN** Ansible Vault, `~/.aws`, CI variables and deployment keys are the material; the inventory file names the hosts they reach
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `linux-lateral-movement` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A local privilege boundary rather than a host hop | [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) | Escalation rather than movement |
| The share is NFS and root-squashed | [`linux-privilege-escalation-nfs-and-share-abuse`](../linux-privilege-escalation-nfs-and-share-abuse/SKILL.md) | Ownership and squash semantics |
| The network path must be tunnelled | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Routing to an unreachable host |
| The destination is a Windows host | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | Different credential semantics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the credential material and its scope.** Private keys under `~/.ssh`, agent sockets, `.netrc` and `.pgpass` files, cloud credential files, and automation secrets. For each, record the file's permissions, the owning account, and any `from=` or `command=` restriction in the matching `authorized_keys`.
2. **Establish the trust topology rather than guessing it.** `known_hosts` names the hosts the account has contacted; the Ansible or Puppet inventory names the hosts the automation manages; the NFS mount table names the central filer. These three reads give the reachability graph without a single connection attempt.
3. **Baseline the account's normal movement.** A deployment account that connects to fifty hosts nightly has a broad baseline. The differential is a source host or a destination that never appears in that account's history, which is what distinguishes movement from routine automation.
4. **Name the stop condition and the containment rule.** Stop at the first host reached with a credential that was not intended to reach it. Copying keys or adding `authorized_keys` entries changes production state; prove reachability with an authentication attempt that runs a read-only command.
5. **State the proof.** Proof is the credential, its permission, the target's `sshd` log showing the accepted key fingerprint, and the host's own record of the session. A successful `ssh` banner is not proof of authorisation; the target-side log is.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Private key with mode 0600 readable by the current user | Proves the key is usable for authentication, provided the target's `authorized_keys` accepts it; any Linux host. |
| `authorized_keys` entry with `from=` restriction | Proves the key is scoped to a source address, which bounds the movement to that network; any Linux host. |
| `SSH_AUTH_SOCK` set with a live agent | Proves keys can be used without reading them, while the agent's parent session lives; any Linux host with agent forwarding. |
| NFS-mounted home directory shared across hosts | Proves one host's compromise reaches every other host that mounts the same home, including its `authorized_keys`; any estate with a central filer. |
| Ansible inventory naming hosts the account manages | Proves the automation credential's reach, which is usually far broader than the operator's own access; any estate with configuration management. |

## Worked Contrast

**Weak configuration — one shared deployment key authorised on every host with no source restriction:**

```bash
# ~/.ssh/authorized_keys on every host
ssh-ed25519 AAAAC3Nza... deploy@ci
# no from= restriction and no command= restriction, and the same key is on all
# 400 hosts, so any host's copy provides access to all of them
```

**Hardened configuration — per-host keys with source restriction and a forced command:**

```bash
# per-host key, restricted to the automation subnet and to one command
from="10.20.99.0/24",command="/usr/local/sbin/deploy-hook",no-port-forwarding,no-agent-forwarding \
  ssh-ed25519 AAAAC3Nza... deploy@ci-host01
# verification: ssh -t from another source is refused and the key cannot open a shell
```

**Why this matters:** the reach is the key's authorisation breadth, so the controls are per-host keys with `from=` and `command=` restrictions, verified by a refused connection from an unexpected source.

## When It Is NOT This Issue

- **A key that exists but is not authorised anywhere.** A private key without a matching `authorized_keys` entry authenticates to nothing; check the target side before reporting reach.
- **Automation connecting to many hosts.** A deployment account with a broad inventory is designed that way; the finding is an unexpected host in its history, not the breadth itself.
- **A shared home directory mounted read-only.** Reads are possible but `authorized_keys` cannot be modified; the finding is bounded to data disclosure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `linux-lateral-movement` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `linux-lateral-movement` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: linux-lateral-movement
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `linux-lateral-movement` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1021`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (2), CYBER_CPT/github_security_md (2), CYBER_CPT/hacktricks (1), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
