---
name: linux-privilege-escalation-kernel-and-container-escapes
description: Linux kernel and container boundary escalation. Covers kernel CVE escalation, container escape through privileged mounts, docker socket exposure and cgroup release_agent paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["linux kernel exploit", "container escape", "docker socket", "privileged container escape"]
cwe: [CWE-269]
owasp: []
attack: [T1068]
capec: [CAPEC-233]
related: [linux-privilege-escalation, linux-privilege-escalation-sudo-abuse, linux-privilege-escalation-suid-and-capabilities, linux-privilege-escalation-cron-and-systemd]
parent: linux-privilege-escalation
---

# Linux Privilege Escalation Kernel and Container Escapes - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md)

## Mechanism and Preconditions

Kernel privilege escalation exploits a bug in the kernel's own handling of a system call, while container escape exploits the fact that a container is a set of namespaces rather than a virtual machine: a shared kernel, a mounted socket, an over-privileged capability set, or a host path bind-mount all provide a path out. The two share a methodology — establish the exact kernel version and the exact container configuration, because distribution backports and runtime defaults decide whether a named vulnerability or escape primitive applies at all.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the kernel version looks old **THEN** check the distribution's changelog; a backported fix leaves the version string unchanged, so the version alone is not evidence
3. **IF** the process is inside a container **THEN** enumerate the namespace and mount configuration before considering the kernel, since a socket or host path is usually the simpler path
4. **IF** `/var/run/docker.sock` is mounted **THEN** the socket is equivalent to root on the host; that is the finding
5. **IF** the container runs `--privileged` or with `CAP_SYS_ADMIN` **THEN** a mount or namespace operation becomes available; that is the finding
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `linux-privilege-escalation-kernel-and-container-escapes` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A scheduled job or unit is the artefact | [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) | Timed execution as root |
| A sudo rule is the artefact | [`linux-privilege-escalation-sudo-abuse`](../linux-privilege-escalation-sudo-abuse/SKILL.md) | Delegated execution |
| The driver-class equivalent on Windows | [`windows-privilege-escalation-kernel-and-driver-escalation`](../windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | Kernel primitives in a different OS |
| The container is a Kubernetes workload | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Reaching the cluster network |
| Need the class-level branch table first | [`linux-privilege-escalation`](../linux-privilege-escalation/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix the kernel identity with the distribution's build string.** `uname -a` gives the version, and the distribution's package version plus changelog decides which fixes are present. A CVE claim without the package version is unfalsifiable, and a version-based claim without the changelog is usually wrong.
2. **Determine whether the process is containerised and how.** `/proc/1/cgroup`, the presence of `/.dockerenv`, the mount table, and the capability set. The escape technique follows from the configuration: a mounted socket, a host path, an over-broad capability, or a shared namespace.
3. **Baseline against the same image run with a hardened profile.** The same container with a read-only root filesystem, no host mounts, dropped capabilities and a non-root user is the reference. Any difference in socket mounts, capabilities or host paths is the finding.
4. **Set the stop condition before any exploit.** Kernel exploits crash hosts. Name the acceptance: version and package evidence is sufficient for a report, and running the exploit is a separate decision with its own authorisation and a snapshot taken first.
5. **State the proof.** Proof is the kernel package version against the vendor advisory, or the container configuration: the socket mount, the capability set, the host path, or the privileged flag. The exploit result is confirmation, not the evidence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `uname -r` plus distribution package version | Proves the kernel build under assessment, which is the only defensible basis for a CVE claim; any Linux host. |
| `/var/run/docker.sock` in the mount table | Proves the host container runtime is controllable from inside, which is root on the host; containerised workloads. |
| `CAP_SYS_ADMIN` in the effective set | Proves mount and namespace operations are permitted, which is the standard escape precondition; containers without a capability drop. |
| Host path bind-mounted into the container | Proves direct read or write on a host path, with the blast radius set by the path; containerised workloads. |
| `/proc/self/status` `CapEff` value | Proves the effective capability set of the running process, which is the container's real privilege; any Linux host. |

## Worked Contrast

**Weak configuration — a container with the host runtime socket mounted and no capability drop:**

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock --privileged app:latest
# the socket lets the container start a host-privileged container,
# and --privileged removes every remaining restriction
```

**Hardened configuration — no runtime socket, capabilities dropped, read-only root, non-root user:**

```bash
docker run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --user 10001:10001 app:latest
# verification: the mount table shows no runtime socket and CapEff decodes to an empty set
```

**Why this matters:** escape is a configuration property, so the control is the mount and capability profile and the verification is the mount table plus the effective capability set.

## When It Is NOT This Issue

- **A kernel version matching a CVE that the distribution backported.** The fix is in the package even though the version string predates it; check the changelog.
- **A container with a socket mounted for a documented management purpose.** Some agent containers legitimately mount the runtime socket; the finding is the workload's own profile, not the platform agent.
- **User namespaces enabled on the host.** Their presence is not an escape; the finding is a container that can create them with elevated mapping.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `linux-privilege-escalation-kernel-and-container-escapes` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `linux-privilege-escalation-kernel-and-container-escapes` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: linux-privilege-escalation-kernel-and-container-escapes
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
- [`linux-privilege-escalation-nfs-and-share-abuse`](../linux-privilege-escalation-nfs-and-share-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `linux-privilege-escalation-kernel-and-container-escapes` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1068`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 18 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/awesome_list (5), bugbounty-hunter-v1 (3), CYBER_CPT/github_security_md (3), hackerone_disclosed_reports (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 11 cases |
| Grounding | multi-dataset corpus-grounded |
